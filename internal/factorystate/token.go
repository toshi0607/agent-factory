package factorystate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/toshi0607/agent-factory/internal/claudeauth"
)

const (
	tokenLifetime   = 600 * time.Second
	refreshMargin   = 2 * time.Minute
	storageScope    = "https://www.googleapis.com/auth/devstorage.read_write"
	stsScope        = "https://www.googleapis.com/auth/cloud-platform"
	tokenExchange   = "urn:ietf:params:oauth:grant-type:token-exchange"
	jwtTokenType    = "urn:ietf:params:oauth:token-type:jwt"
	accessTokenType = "urn:ietf:params:oauth:token-type:access_token"
)

type tokenSource struct {
	google         *googleHTTP
	oidcHTTP       *http.Client
	oidc           claudeauth.Config
	serviceAccount string
	now            func() time.Time

	mu        sync.Mutex
	token     string
	expiresAt time.Time
	exchanges int
}

func newTokenSource(cfg Config, google *googleHTTP, oidcHTTP *http.Client, oidc claudeauth.Config) *tokenSource {
	// The provider accepts the https form as the ID token audience by default;
	// the STS request names the same provider in the scheme-less form.
	oidc.Audience = "https://iam.googleapis.com/" + cfg.Provider
	return &tokenSource{google: google, oidcHTTP: oidcHTTP, oidc: oidc, serviceAccount: cfg.ServiceAccount, now: time.Now}
}

// Token returns a cached service-account access token, refreshing it when
// less than two minutes remain.
func (t *tokenSource) Token(ctx context.Context) (string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if t.token != "" && t.expiresAt.Sub(t.now()) >= refreshMargin {
		return t.token, nil
	}
	token, expiresAt, err := t.refresh(ctx)
	if err != nil {
		return "", err
	}
	t.token, t.expiresAt = token, expiresAt
	t.exchanges++
	return token, nil
}

func (t *tokenSource) refresh(ctx context.Context) (string, time.Time, error) {
	if !fullSHA(t.oidc.ExpectedWorkflowSHA) {
		return "", time.Time{}, errors.New("FACTORY_COMMIT must be the full factory commit SHA to check the OIDC job_workflow_sha")
	}
	jwt, _, err := claudeauth.RequestOIDC(ctx, t.oidcHTTP, t.oidc)
	if err != nil {
		return "", time.Time{}, err
	}
	form := url.Values{
		"grant_type":           {tokenExchange},
		"audience":             {strings.TrimPrefix(t.oidc.Audience, "https:")},
		"scope":                {stsScope},
		"requested_token_type": {accessTokenType},
		"subject_token":        {jwt},
		"subject_token_type":   {jwtTokenType},
	}
	var federated struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
	}
	if err := t.post(ctx, stsURL, "application/x-www-form-urlencoded", []byte(form.Encode()), "", "Google STS token exchange", &federated); err != nil {
		return "", time.Time{}, err
	}
	if !validToken(federated.AccessToken) || !strings.EqualFold(federated.TokenType, "Bearer") {
		return "", time.Time{}, errors.New("Google STS token exchange returned an invalid token")
	}
	body, err := json.Marshal(struct {
		Scope    []string `json:"scope"`
		Lifetime string   `json:"lifetime"`
	}{[]string{storageScope}, "600s"})
	if err != nil {
		return "", time.Time{}, errors.New("could not encode the impersonation request")
	}
	start := t.now()
	var impersonated struct {
		AccessToken string    `json:"accessToken"`
		ExpireTime  time.Time `json:"expireTime"`
	}
	target := iamURL + url.PathEscape(t.serviceAccount) + ":generateAccessToken"
	if err := t.post(ctx, target, "application/json", body, federated.AccessToken, "service-account impersonation", &impersonated); err != nil {
		return "", time.Time{}, err
	}
	if !validToken(impersonated.AccessToken) || !impersonated.ExpireTime.After(start) {
		return "", time.Time{}, errors.New("service-account impersonation returned an invalid token")
	}
	return impersonated.AccessToken, earliest(impersonated.ExpireTime, start.Add(tokenLifetime)), nil
}

func earliest(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func (t *tokenSource) post(ctx context.Context, target, contentType string, body []byte, bearer, operation string, out any) error {
	ctx, cancel := context.WithTimeout(ctx, t.google.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return errors.New(operation + ": could not construct the request")
	}
	req.Header.Set("Content-Type", contentType)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := t.google.do(req, operation)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return responseError(resp, operation)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, errorBodyLimit)).Decode(out); err != nil {
		return errors.New(operation + " returned invalid JSON")
	}
	return nil
}

func validToken(token string) bool {
	return token != "" && len(token) <= 4096 && strings.IndexFunc(token, func(r rune) bool { return r <= ' ' || r >= 127 }) == -1
}

func fullSHA(value string) bool {
	if len(value) != 40 {
		return false
	}
	for _, r := range value {
		if !strings.ContainsRune("0123456789abcdefABCDEF", r) {
			return false
		}
	}
	return true
}
