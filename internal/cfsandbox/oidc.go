package cfsandbox

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/toshi0607/agent-factory/internal/claudeauth"
)

type OIDCAuthenticator struct {
	client *http.Client
	cfg    claudeauth.Config

	mu        sync.Mutex
	token     string
	fetchedAt time.Time
	expiresAt time.Time
}

func NewOIDCAuthenticator(client *http.Client, cfg claudeauth.Config) *OIDCAuthenticator {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &OIDCAuthenticator{client: client, cfg: cfg}
}

func (a *OIDCAuthenticator) Authorize(ctx context.Context, req *http.Request) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	now := a.cfg.Now()
	if a.token == "" || now.Sub(a.fetchedAt) >= 4*time.Minute || a.expiresAt.Sub(now) <= time.Minute {
		token, expiresAt, err := claudeauth.RequestOIDC(ctx, a.client, a.cfg)
		if err != nil {
			return err
		}
		a.token, a.fetchedAt, a.expiresAt = token, now, expiresAt
	}
	req.Header.Set("Authorization", "Bearer "+a.token)
	return nil
}
