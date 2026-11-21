package claudeauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

func (f *Federation) requestOIDC(ctx context.Context, secrets ...string) (string, error) {
	if f.cfg.OIDCURL == "" || f.cfg.OIDCRequestToken == "" {
		return "", errors.New("ACTIONS_ID_TOKEN_REQUEST_URL and ACTIONS_ID_TOKEN_REQUEST_TOKEN are required")
	}
	oidcURL, err := url.Parse(f.cfg.OIDCURL)
	if err != nil || oidcURL.Hostname() == "" || oidcURL.User != nil ||
		(oidcURL.Scheme != "https" && oidcURL.Scheme != "http") {
		return "", errors.New("invalid GitHub Actions OIDC request URL")
	}
	query := oidcURL.Query()
	query.Set("audience", f.cfg.Audience)
	oidcURL.RawQuery = query.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, oidcURL.String(), nil)
	if err != nil {
		return "", errors.New("could not construct GitHub Actions OIDC request")
	}
	req.Header.Set("Authorization", "Bearer "+f.cfg.OIDCRequestToken)
	var oidc struct {
		Value string `json:"value"`
	}
	if err := f.readJSON(req, "GitHub Actions OIDC request", &oidc, secrets...); err != nil {
		return "", err
	}
	if !validBearer(oidc.Value) {
		return "", errors.New("GitHub Actions OIDC response has no valid value")
	}
	return oidc.Value, nil
}

// OIDCClaims requests a fresh GitHub OIDC token and decodes its diagnostic claims.
func (f *Federation) OIDCClaims(ctx context.Context) (map[string]any, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	jwt, err := f.requestOIDC(ctx)
	if err != nil {
		return nil, err
	}
	raw, err := decodeOIDCClaims(jwt)
	if err != nil {
		return nil, err
	}
	claims := make(map[string]any)
	for _, name := range []string{
		"iss", "sub", "aud", "repository", "repository_owner", "repository_visibility",
		"ref", "sha", "event_name", "workflow", "workflow_ref", "job_workflow_ref",
		"job_workflow_sha", "runner_environment",
	} {
		data, ok := raw[name]
		if !ok {
			continue
		}
		var value string
		if json.Unmarshal(data, &value) == nil {
			claims[name] = redact(value, f.cfg.OIDCRequestToken, jwt)
			continue
		}
		if name == "aud" {
			var audience []string
			if json.Unmarshal(data, &audience) == nil {
				for i, value := range audience {
					audience[i] = redact(value, f.cfg.OIDCRequestToken, jwt)
				}
				claims[name] = audience
				continue
			}
		}
		return nil, errors.New("GitHub Actions OIDC JWT has invalid diagnostic claim type")
	}
	return claims, nil
}

var fullCommitSHA = regexp.MustCompile(`^[a-fA-F0-9]{40}$`)

func checkWorkflowSHA(jwt, expected string) error {
	raw, err := decodeOIDCClaims(jwt)
	if err != nil {
		return err
	}
	var actual string
	if data := raw["job_workflow_sha"]; data != nil {
		if err := json.Unmarshal(data, &actual); err != nil || !fullCommitSHA.MatchString(actual) {
			actual = "<invalid SHA>"
		}
	}
	validExpected := fullCommitSHA.MatchString(expected)
	if validExpected && strings.EqualFold(actual, expected) {
		return nil
	}
	// Only print full commit IDs, never arbitrary values from the JWT or environment.
	if expected != "" && !validExpected {
		expected = "<invalid SHA>"
	}
	return fmt.Errorf("GitHub Actions OIDC job_workflow_sha %q does not match FACTORY_COMMIT %q (both must be full commit SHAs)", actual, expected)
}

func decodeOIDCClaims(jwt string) (map[string]json.RawMessage, error) {
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return nil, errors.New("GitHub Actions OIDC response is not a JWT")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, errors.New("GitHub Actions OIDC JWT has invalid payload encoding")
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(payload, &raw); err != nil || raw == nil {
		return nil, errors.New("GitHub Actions OIDC JWT has invalid claims")
	}
	return raw, nil
}
