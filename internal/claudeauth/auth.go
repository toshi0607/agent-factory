// Package claudeauth authorizes Claude API requests.
package claudeauth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode"
)

const defaultAudience = "https://api.anthropic.com"
const jwtBearerGrant = "urn:ietf:params:oauth:grant-type:jwt-bearer"

type Static struct {
	Header string
	Value  string
}

func (s Static) Authorize(_ context.Context, req *http.Request) error {
	req.Header.Set(s.Header, s.Value)
	return nil
}

type Config struct {
	OIDCURL             string
	OIDCRequestToken    string
	Audience            string
	FederationRuleID    string
	OrganizationID      string
	ServiceAccountID    string
	WorkspaceID         string
	ExpectedWorkflowSHA string
}

func ConfigFromEnv() Config {
	return Config{
		OIDCURL:             os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL"),
		OIDCRequestToken:    os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN"),
		FederationRuleID:    os.Getenv("ANTHROPIC_FEDERATION_RULE_ID"),
		OrganizationID:      os.Getenv("ANTHROPIC_ORGANIZATION_ID"),
		ServiceAccountID:    os.Getenv("ANTHROPIC_SERVICE_ACCOUNT_ID"),
		WorkspaceID:         os.Getenv("ANTHROPIC_WORKSPACE_ID"),
		ExpectedWorkflowSHA: os.Getenv("FACTORY_COMMIT"),
	}
}

type TokenInfo struct {
	ExpiresIn int64  `json:"expires_in"`
	Scope     string `json:"scope"`
}

type Federation struct {
	client   http.Client
	endpoint string
	cfg      Config
	now      func() time.Time

	mu        sync.Mutex
	token     string
	expiresAt time.Time
	info      TokenInfo
}

func NewFederation(base string, client *http.Client, cfg Config) *Federation {
	if base == "" {
		base = defaultAudience
	}
	if client == nil {
		client = http.DefaultClient
	}
	if cfg.Audience == "" {
		cfg.Audience = defaultAudience
	}
	f := &Federation{client: *client, endpoint: strings.TrimRight(base, "/") + "/v1/oauth/token", cfg: cfg, now: time.Now}
	// Redirects could forward GitHub's bearer header or the JWT exchange body.
	f.client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return f
}

func (f *Federation) Authorize(ctx context.Context, req *http.Request) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if f.token == "" || f.expiresAt.Sub(f.now()) < time.Minute {
		if err := f.refresh(ctx); err != nil {
			return err
		}
	}
	req.Header.Set("Authorization", "Bearer "+f.token)
	return nil
}

// Info returns metadata from the most recent successful exchange.
func (f *Federation) Info() (TokenInfo, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.info, f.token != ""
}

func (f *Federation) refresh(ctx context.Context) error {
	if f.cfg.OIDCURL == "" || f.cfg.OIDCRequestToken == "" {
		return errors.New("ACTIONS_ID_TOKEN_REQUEST_URL and ACTIONS_ID_TOKEN_REQUEST_TOKEN are required")
	}
	if f.cfg.FederationRuleID == "" || f.cfg.OrganizationID == "" {
		return errors.New("ANTHROPIC_FEDERATION_RULE_ID and ANTHROPIC_ORGANIZATION_ID are required")
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	jwt, err := f.requestOIDC(ctx, f.token)
	if err != nil {
		return err
	}
	if err := checkWorkflowSHA(jwt, f.cfg.ExpectedWorkflowSHA); err != nil {
		return err
	}

	body, err := json.Marshal(struct {
		GrantType        string `json:"grant_type"`
		Assertion        string `json:"assertion"`
		FederationRuleID string `json:"federation_rule_id"`
		OrganizationID   string `json:"organization_id"`
		ServiceAccountID string `json:"service_account_id,omitempty"`
		WorkspaceID      string `json:"workspace_id,omitempty"`
	}{jwtBearerGrant, jwt, f.cfg.FederationRuleID, f.cfg.OrganizationID, f.cfg.ServiceAccountID, f.cfg.WorkspaceID})
	if err != nil {
		return errors.New("could not encode Anthropic federation request")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, f.endpoint, bytes.NewReader(body))
	if err != nil {
		return errors.New("could not construct Anthropic federation request")
	}
	req.Header.Set("Content-Type", "application/json")
	var exchange struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		TokenInfo
	}
	start := f.now()
	if err := f.readJSON(req, "Anthropic federation exchange", &exchange, jwt, f.token); err != nil {
		return err
	}
	if !validBearer(exchange.AccessToken) || !strings.EqualFold(exchange.TokenType, "Bearer") ||
		exchange.ExpiresIn <= 0 || exchange.ExpiresIn > math.MaxInt64/int64(time.Second) {
		return errors.New("Anthropic federation response has invalid token metadata")
	}
	exchange.Scope = redact(exchange.Scope, f.cfg.OIDCRequestToken, jwt, exchange.AccessToken, f.token)
	f.token = exchange.AccessToken
	f.expiresAt = start.Add(time.Duration(exchange.ExpiresIn) * time.Second)
	f.info = exchange.TokenInfo
	return nil
}

func validBearer(token string) bool {
	return token != "" && strings.IndexFunc(token, func(r rune) bool { return r <= ' ' || r >= 127 }) == -1
}

func (f *Federation) readJSON(req *http.Request, operation string, out any, secrets ...string) error {
	resp, err := f.client.Do(req)
	if err != nil {
		// Transport errors can contain the request URL or values echoed by a proxy.
		return fmt.Errorf("%s failed", operation)
	}
	defer resp.Body.Close()
	body := io.LimitReader(resp.Body, 64<<10)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if diagnostic := errorDiagnostic(body, append(secrets, f.cfg.OIDCRequestToken)...); diagnostic != "" {
			return fmt.Errorf("%s: HTTP %d: %s", operation, resp.StatusCode, diagnostic)
		}
		return fmt.Errorf("%s: HTTP %d", operation, resp.StatusCode)
	}
	if err := json.NewDecoder(body).Decode(out); err != nil {
		return fmt.Errorf("%s returned invalid JSON", operation)
	}
	return nil
}

var credentialPattern = regexp.MustCompile(`eyJ[A-Za-z0-9_-]{20,}|sk-ant-`)

func errorDiagnostic(body io.Reader, secrets ...string) string {
	var fields map[string]json.RawMessage
	data, err := io.ReadAll(body)
	if err != nil || json.Unmarshal(data, &fields) != nil {
		return ""
	}
	asString := func(raw json.RawMessage) string {
		var s string
		if json.Unmarshal(raw, &s) != nil {
			return ""
		}
		return s
	}
	var nested map[string]json.RawMessage
	_ = json.Unmarshal(fields["error"], &nested)
	messages := []string{asString(nested["type"]), asString(nested["message"])}
	if messages[0] == "" && messages[1] == "" {
		messages = []string{asString(fields["error"]), asString(fields["error_description"]), asString(fields["message"])}
	}
	for _, fields := range []map[string]json.RawMessage{fields, nested} {
		secrets = append(secrets, asString(fields["access_token"]), asString(fields["value"]))
	}
	messages = slices.DeleteFunc(messages, func(s string) bool { return strings.TrimSpace(s) == "" })
	diagnostic := redact(strings.Join(messages, ": "), secrets...)
	diagnostic = strings.TrimSpace(strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.IsSpace(r) {
			return ' '
		}
		return r
	}, diagnostic))
	if credentialPattern.MatchString(diagnostic) {
		return ""
	}
	runes := []rune(diagnostic)
	return string(runes[:min(len(runes), 300)])
}

func redact(text string, secrets ...string) string {
	slices.SortFunc(secrets, func(a, b string) int { return len(b) - len(a) })
	var replacements []string
	for _, secret := range secrets {
		if secret != "" {
			replacements = append(replacements, secret, "[redacted]")
		}
	}
	return strings.NewReplacer(replacements...).Replace(text)
}
