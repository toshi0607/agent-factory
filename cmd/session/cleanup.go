package main

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/toshi0607/agent-factory/internal/claude"
)

func (r runner) cleanupAfterRun(ctx context.Context, s state, status string, interrupted bool) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Minute)
	defer cancel()
	return r.cleanup(ctx, s, status, interrupted)
}

func (r runner) cleanup(ctx context.Context, s state, status string, interrupted bool) error {
	if s.Candidate == workerCandidate {
		client, err := r.workerClient()
		if err != nil {
			return err
		}
		if err := client.Delete(ctx, s.WorkID); err != nil {
			return fmt.Errorf("delete worker run: %w", err)
		}
		return nil
	}
	var errs []error
	report := func(resource, id string, err error) {
		if err != nil && !claude.IsNotFound(err) {
			errs = append(errs, fmt.Errorf("could not remove %s %s: %w", resource, id, err))
		}
	}

	if s.SessionID != "" {
		sessionExists := true
		if status == "" {
			session, err := r.api.GetSession(ctx, s.SessionID)
			status = session.Status
			sessionExists = !claude.IsNotFound(err)
		}
		if sessionExists {
			if !settled(status) && !interrupted {
				if err := r.api.Interrupt(ctx, s.SessionID); err == nil {
					_, _ = r.awaitIdle(ctx, s.SessionID)
				}
			}
			report("session", s.SessionID, r.api.DeleteSession(ctx, s.SessionID))
		}
	}
	if s.AgentID != "" {
		report("agent", s.AgentID, r.api.ArchiveAgent(ctx, s.AgentID))
	}
	if s.EnvironmentID != "" {
		report("environment", s.EnvironmentID, r.api.DeleteEnvironment(ctx, s.EnvironmentID))
	}
	for _, id := range s.UploadedFileIDs {
		if id != "" {
			report("file", id, r.api.DeleteFile(ctx, id))
		}
	}
	return errors.Join(errs...)
}
