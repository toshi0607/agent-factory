package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"

	"github.com/toshi0607/agent-factory/internal/cfsandbox"
	"github.com/toshi0607/agent-factory/internal/claudeauth"
	"github.com/toshi0607/agent-factory/internal/delivery"
	"github.com/toshi0607/agent-factory/internal/policy"
)

const (
	workerCandidate      = "cloudflare-sandbox"
	workerMaxMinutes     = 30
	workerMaxBudgetCents = 300
)

func (r runner) workerClient() (*cfsandbox.Client, error) {
	if r.worker != nil {
		return r.worker, nil
	}
	base := os.Getenv("FACTORY_WORKER_URL")
	if base == "" {
		return nil, errors.New("FACTORY_WORKER_URL is required for cloudflare-sandbox")
	}
	cfg := claudeauth.ConfigFromEnv()
	cfg.Audience = os.Getenv("FACTORY_WORKER_AUDIENCE")
	if cfg.Audience == "" {
		return nil, errors.New("FACTORY_WORKER_AUDIENCE is required for cloudflare-sandbox")
	}
	if strings.Contains(strings.ToLower(strings.TrimSpace(cfg.Audience)), "anthropic.com") {
		return nil, errors.New("FACTORY_WORKER_AUDIENCE must not use an Anthropic host")
	}
	if audience, err := url.Parse(strings.TrimSpace(cfg.Audience)); err == nil {
		host := strings.TrimSuffix(strings.ToLower(audience.Hostname()), ".")
		if host == "anthropic.com" || strings.HasSuffix(host, ".anthropic.com") {
			return nil, errors.New("FACTORY_WORKER_AUDIENCE must not use an Anthropic host")
		}
	}
	client, err := cfsandbox.New(base, http.DefaultClient, cfsandbox.NewOIDCAuthenticator(http.DefaultClient, cfg))
	if err != nil {
		return nil, fmt.Errorf("FACTORY_WORKER_URL: %w", err)
	}
	if cfg.OIDCURL == "" || cfg.OIDCRequestToken == "" {
		return nil, errors.New("ACTIONS_ID_TOKEN_REQUEST_URL and ACTIONS_ID_TOKEN_REQUEST_TOKEN are required")
	}
	return client, nil
}

func makeWorkerRequest(cfg policy.Policy, role policy.Role, name, system string, budget, minutes int) (cfsandbox.StartRequest, error) {
	prices, ok := cfg.Pricing[role.Model]
	if !ok {
		return cfsandbox.StartRequest{}, fmt.Errorf("cloudflare-sandbox requires policy pricing for model %q", role.Model)
	}
	if budget > workerMaxBudgetCents || minutes > workerMaxMinutes {
		return cfsandbox.StartRequest{}, fmt.Errorf("worker limits are %d budget cents and %d minutes", workerMaxBudgetCents, workerMaxMinutes)
	}
	request := cfsandbox.StartRequest{
		Role: name, Model: role.Model, SystemPrompt: system,
		UserMessage: formatUserMessage("/factory/delivery/setup.sh", "/factory/delivery/task.md", "/factory/delivery/finish.sh"),
		BudgetCents: budget, Minutes: minutes, Prices: prices,
		Egress: []policy.PathRule{},
	}
	hosts := make(map[string]int)
	add := func(host string, prefixes []string) {
		i, ok := hosts[host]
		if !ok {
			i = len(request.Egress)
			hosts[host] = i
			request.Egress = append(request.Egress, policy.PathRule{Host: host})
		}
		for _, prefix := range prefixes {
			if !slices.Contains(request.Egress[i].PathPrefixes, prefix) {
				request.Egress[i].PathPrefixes = append(request.Egress[i].PathPrefixes, prefix)
			}
		}
	}
	for _, name := range role.Egress {
		rule := cfg.Egress[name]
		for _, host := range rule.AllowedHosts {
			add(host, nil)
		}
		for _, entry := range rule.PathRules {
			add(entry.Host, entry.PathPrefixes)
		}
	}
	return request, nil
}

func (r runner) startWorker(ctx context.Context, root *os.Root, manifest delivery.Manifest, manifestData []byte, goArchive string, request cfsandbox.StartRequest, s state, statePath string) error {
	for _, entry := range manifest.Files {
		if entry.Name == goArchive {
			continue
		}
		f, err := openPrepared(root, entry)
		if err != nil {
			return fmt.Errorf("open %s: %w", entry.Name, err)
		}
		err = r.worker.PutFile(ctx, s.WorkID, entry.Name, f, entry.Bytes)
		f.Close()
		if err != nil {
			return fmt.Errorf("upload %s: %w", entry.Name, err)
		}
	}
	if err := r.worker.PutFile(ctx, s.WorkID, delivery.ManifestName, bytes.NewReader(manifestData), int64(len(manifestData))); err != nil {
		return fmt.Errorf("upload manifest: %w", err)
	}
	if err := r.pushWorkerToken(ctx, s.WorkID); err != nil {
		return err
	}
	s.WorkerTokenPushedAt = new(r.clock.Now().UTC())
	started, err := r.worker.Start(ctx, s.WorkID, request)
	if err != nil {
		return fmt.Errorf("start worker run: %w", err)
	}
	if started.State != "running" || started.StartedAt.IsZero() {
		return errors.New("worker start response did not include a running state and start time")
	}
	s.SessionID = s.WorkID
	s.StartedAt = started.StartedAt
	s.WorkerVersion = started.WorkerVersion.ID
	s.WorkerFactoryCommit = started.FactoryCommit
	s.AgentRequestSHA256 = started.RequestSHA256
	s.EnvironmentRequestSHA256 = started.RequestSHA256
	if err := writeJSON(statePath, s, delivery.WriteAtomic); err != nil {
		return fmt.Errorf("update state file: %w", err)
	}
	return nil
}

func (r runner) pushWorkerToken(ctx context.Context, id string) error {
	if r.auth == nil {
		return errors.New("worker token requires Anthropic federation")
	}
	token, seconds, err := r.auth.Token(ctx)
	if err != nil {
		return fmt.Errorf("get federated token for worker: %w", err)
	}
	if err := r.worker.PutToken(ctx, id, token, min(seconds, 86400)); err != nil {
		return fmt.Errorf("push federated token to worker: %w", err)
	}
	return nil
}
