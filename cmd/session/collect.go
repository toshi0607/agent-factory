package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/toshi0607/agent-factory/internal/claude"
	"github.com/toshi0607/agent-factory/internal/delivery"
	"github.com/toshi0607/agent-factory/poc/record"
)

const (
	interruptGrace      = 60 * time.Second
	startupGrace        = 120 * time.Second
	interruptAttempts   = 3
	interruptRetryDelay = 2 * time.Second
	stopCompleted       = "completed"
	stopBudgetReached   = "budget_reached"
	stopTimeLimit       = "time_limit"
	stopNeverStarted    = "never_started"
	patchName           = "patch.diff"
	pathsName           = "changed-paths.txt"
	probeName           = "probe.txt"
)

func validMinutes(minutes int) bool {
	return minutes > 0 && int64(minutes) <= math.MaxInt64/int64(time.Minute)
}

const recoveryHint = `run the "factory-p0-recover" workflow with this run's id to collect again or clean up`

func (r runner) collect(ctx context.Context, s state, out string) (resultErr error) {
	start := r.clock.Now()
	var session claude.Session
	var stopReason string
	recordSaved := false
	stopAttempted := false
	defer func() {
		if resultErr == nil || recordSaved || s.SessionID == "" {
			return
		}
		resultErr = r.handleCollectFailure(ctx, s, session.Status, stopAttempted, resultErr)
	}()
	if s.SessionID == "" || !validMinutes(s.MinutesLimit) || s.StartedAt.IsZero() {
		return errors.New("state requires a session ID, positive minutes limit, and start time")
	}
	if err := os.MkdirAll(out, 0o755); err != nil {
		return err
	}

	deadline := s.StartedAt.Add(time.Duration(s.MinutesLimit) * time.Minute)
	session, stopReason, resultErr = r.waitForCompletion(ctx, s.SessionID, s.StartedAt, deadline)
	if resultErr != nil {
		return resultErr
	}
	if stopReason == stopTimeLimit {
		session, resultErr = r.interruptAndWait(ctx, s.SessionID)
		if resultErr != nil {
			stopAttempted = true
			return fmt.Errorf("stop session at time limit: %w", resultErr)
		}
	}

	patch, notes, err := r.collectOutputs(ctx, s, out)
	if err != nil {
		return err
	}
	events, truncated, err := r.api.ListEvents(ctx, s.SessionID)
	if truncated {
		notes = append(notes, "event listing was truncated")
	}
	if err != nil {
		notes = append(notes, fmt.Sprintf("could not list session events: %v", err))
	} else if err := writeBytes(filepath.Join(out, "events.json"), events); err != nil {
		notes = append(notes, fmt.Sprintf("could not save session events: %v", err))
	}
	if err == nil && stopReason == stopCompleted && lastIdleReachedBudget(events) {
		stopReason = stopBudgetReached
	} else if truncated && stopReason == stopCompleted {
		notes = append(notes, "stop reason could not be confirmed from a truncated event listing")
	}
	final, err := r.api.GetSession(ctx, s.SessionID)
	if err != nil {
		return fmt.Errorf("read final session: %w", err)
	}
	session = final
	if !settled(session.Status) {
		return errors.New("final session status is not settled")
	}
	finished := r.clock.Now().UTC()
	webToolsUsed := session.Usage.ServerToolUse.WebFetchRequests != 0 || session.Usage.ServerToolUse.WebSearchRequests != 0
	const webToolViolation = "policy violation: the agent used web tools"
	if webToolsUsed {
		notes = append(notes, webToolViolation)
	}
	if stopReason == stopNeverStarted {
		notes = append(notes, "Session remained idle with no activity for more than 120 seconds.")
	}
	rec := record.Record{
		SchemaVersion: 1, Candidate: s.Candidate, Task: s.Task, WorkID: s.WorkID,
		BaseCommit: s.BaseCommit, FactoryCommit: s.FactoryCommit, Role: s.Role, Model: s.Model,
		EnvironmentRequestSHA256: s.EnvironmentRequestSHA256, AgentRequestSHA256: s.AgentRequestSHA256,
		BudgetCents: s.BudgetCents, MinutesLimit: s.MinutesLimit, StopReason: stopReason,
		StartedAt: s.StartedAt, FinishedAt: finished,
		Session: record.Session{
			ID: s.SessionID, Status: session.Status,
			ActiveSeconds: session.Stats.ActiveSeconds, DurationSeconds: session.Stats.DurationSeconds,
		},
		Usage: record.Usage{
			InputTokens:                session.Usage.InputTokens,
			OutputTokens:               session.Usage.OutputTokens,
			CacheReadInputTokens:       session.Usage.CacheReadInputTokens,
			CacheCreation5mInputTokens: session.Usage.CacheCreation.Ephemeral5mInputTokens,
			CacheCreation1hInputTokens: session.Usage.CacheCreation.Ephemeral1hInputTokens,
			ReportedCost:               record.ReportedCost(session.Usage.ListCost),
			WebFetchRequests:           session.Usage.ServerToolUse.WebFetchRequests,
			WebSearchRequests:          session.Usage.ServerToolUse.WebSearchRequests,
		},
		RunnerSeconds: record.RunnerSeconds{Collect: finished.Sub(start).Seconds()},
		Interruptions: record.Interruptions{Notes: []string{}},
		Egress: record.Egress{
			DeniedDestinations: []string{},
			Notes:              "Managed Agents exposes no network log.",
		},
		Patch: patch, Notes: strings.Join(notes, "\n"),
	}
	if stopReason == stopTimeLimit {
		rec.Interruptions = record.Interruptions{Count: 1, Notes: []string{"Session time limit reached."}}
	}
	if err := writeJSON(filepath.Join(out, "record.partial.json"), rec, delivery.WriteAtomic); err != nil {
		return err
	}
	recordSaved = true
	cleanupErr := r.cleanupAfterRun(ctx, s, session.Status, stopReason == stopTimeLimit)
	if webToolsUsed {
		return errors.Join(errors.New(webToolViolation), cleanupErr)
	}
	return cleanupErr
}

func lastIdleReachedBudget(events []byte) bool {
	var page struct {
		Data []struct {
			Type       string          `json:"type"`
			StopReason json.RawMessage `json:"stop_reason"`
		} `json:"data"`
	}
	if err := json.Unmarshal(events, &page); err != nil {
		return false
	}
	for _, event := range slices.Backward(page.Data) {
		if event.Type != "session.status_idle" {
			continue
		}
		var reason struct {
			Type string `json:"type"`
		}
		return json.Unmarshal(event.StopReason, &reason) == nil && reason.Type == stopBudgetReached
	}
	return false
}

func settled(status string) bool { return status == "idle" || status == "terminated" }

func (r runner) handleCollectFailure(ctx context.Context, s state, status string, stopAttempted bool, err error) error {
	// Filesystem diagnostics can contain runner-local paths.
	if pathErr, ok := errors.AsType[*os.PathError](err); ok {
		err = fmt.Errorf("%s: %w", pathErr.Op, pathErr.Err)
	} else if linkErr, ok := errors.AsType[*os.LinkError](err); ok {
		err = fmt.Errorf("%s: %w", linkErr.Op, linkErr.Err)
	}
	ctx = context.WithoutCancel(ctx)
	if !stopAttempted && !settled(status) {
		var pollErr error
		if status == "" {
			var session claude.Session
			pollCtx, cancel := context.WithTimeout(ctx, interruptGrace)
			session, pollErr = r.api.GetSession(pollCtx, s.SessionID)
			cancel()
			if pollErr == nil {
				status = session.Status
			}
		}
		if !settled(status) && !claude.IsNotFound(pollErr) {
			session, stopErr := r.interruptAndWait(ctx, s.SessionID)
			status = session.Status
			err = errors.Join(err, stopErr)
		}
	}
	if settled(status) {
		return fmt.Errorf("%w; resources were kept (session settled)\nresources were kept; %s", err, recoveryHint)
	}
	deleteCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	deleteErr := r.api.DeleteSession(deleteCtx, s.SessionID)
	cancel()
	if deleteErr != nil && !claude.IsNotFound(deleteErr) {
		return fmt.Errorf("%w; session could not be stopped or deleted; %s", errors.Join(err, deleteErr), recoveryHint)
	}
	s.SessionID = ""
	return errors.Join(fmt.Errorf("%w; session could not be stopped and was deleted", err), r.cleanupAfterRun(ctx, s, "", false))
}

func (r runner) interruptAndWait(ctx context.Context, id string) (claude.Session, error) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Minute)
	defer cancel()
	var interruptErr error
	for attempt := range interruptAttempts {
		if attempt > 0 {
			if err := r.clock.Sleep(ctx, interruptRetryDelay); err != nil {
				interruptErr = errors.Join(interruptErr, err)
				break
			}
		}
		interruptErr = r.api.Interrupt(ctx, id)
		if interruptErr == nil || claude.IsNotFound(interruptErr) {
			break
		}
	}
	if interruptErr != nil {
		interruptErr = fmt.Errorf("interrupt session: %w", interruptErr)
	}
	session, waitErr := r.awaitIdle(ctx, id)
	if waitErr == nil && !settled(session.Status) {
		waitErr = errors.New("session did not settle after the interrupt")
	}
	return session, errors.Join(interruptErr, waitErr)
}

func (r runner) waitForCompletion(ctx context.Context, id string, startedAt, deadline time.Time) (claude.Session, string, error) {
	for {
		session, err := r.api.GetSession(ctx, id)
		if err != nil {
			return claude.Session{}, "", fmt.Errorf("poll session: %w", err)
		}
		now := r.clock.Now()
		if session.Status == "terminated" || (session.Status == "idle" && session.Usage.ActiveSeconds > 0) {
			return session, stopCompleted, nil
		}
		if session.Status == "idle" && session.Usage.ActiveSeconds == 0 && now.Sub(startedAt) > startupGrace {
			return session, stopNeverStarted, nil
		}
		remaining := deadline.Sub(now)
		if remaining <= 0 {
			return session, stopTimeLimit, nil
		}
		if err := r.clock.Sleep(ctx, min(remaining, r.pollInterval)); err != nil {
			return claude.Session{}, "", err
		}
	}
}

func (r runner) awaitIdle(ctx context.Context, id string) (claude.Session, error) {
	ctx, cancel := context.WithTimeout(ctx, interruptGrace)
	defer cancel()
	deadline := r.clock.Now().Add(interruptGrace)
	var session claude.Session
	for {
		if !r.clock.Now().Before(deadline) {
			return session, nil
		}
		current, err := r.api.GetSession(ctx, id)
		if err != nil {
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				return session, nil
			}
			return session, err
		}
		session = current
		remaining := deadline.Sub(r.clock.Now())
		if settled(session.Status) || remaining <= 0 {
			return session, nil
		}
		if err := r.clock.Sleep(ctx, min(remaining, r.pollInterval)); err != nil {
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				return session, nil
			}
			return session, err
		}
	}
}

func (r runner) collectOutputs(ctx context.Context, s state, out string) (record.Patch, []string, error) {
	patch := record.Patch{Paths: []string{}}
	files, notes, err := r.outputFiles(ctx, s.SessionID)
	if err != nil {
		return patch, nil, err
	}
	if files[patchName] == "" || files[pathsName] == "" || (s.Role == "probe" && files[probeName] == "") {
		// Outputs can become visible shortly after the status changes to idle.
		if err := r.clock.Sleep(ctx, r.pollInterval); err != nil {
			return patch, nil, err
		}
		var newNotes []string
		files, newNotes, err = r.outputFiles(ctx, s.SessionID)
		if err != nil {
			return patch, nil, err
		}
		for _, note := range newNotes {
			if !slices.Contains(notes, note) {
				notes = append(notes, note)
			}
		}
	}

	patchPath := filepath.Join(out, patchName)
	pathsPath := filepath.Join(out, pathsName)
	for _, name := range []string{patchName, pathsName, probeName} {
		if err := r.saveOutput(ctx, files[name], filepath.Join(out, name)); err != nil {
			return patch, nil, fmt.Errorf("save %s: %w", name, err)
		}
	}
	if files[pathsName] != "" {
		data, err := os.ReadFile(pathsPath)
		if err != nil {
			return patch, nil, err
		}
		for line := range strings.SplitSeq(strings.TrimSuffix(string(data), "\n"), "\n") {
			if line != "" {
				patch.Paths = append(patch.Paths, line)
			}
		}
	}
	if files[patchName] == "" {
		return patch, append(notes, "patch.diff was not found in session outputs."), nil
	}
	info, err := delivery.Inspect(patchPath)
	if err != nil {
		return patch, nil, err
	}
	patch.SHA256, patch.Bytes = info.SHA256, info.Bytes
	return patch, notes, nil
}

func (r runner) outputFiles(ctx context.Context, id string) (map[string]string, []string, error) {
	files, truncated, err := r.api.ListSessionFiles(ctx, id)
	if err != nil {
		return nil, nil, err
	}
	var notes []string
	if truncated {
		notes = append(notes, "file listing was truncated")
	}
	ids := make(map[string]string)
	for _, name := range []string{patchName, pathsName, probeName} {
		var count int
		var latest, last string
		var newest time.Time
		parseFailed := false
		for _, f := range files {
			if path.Base(f.Filename) != name {
				continue
			}
			count++
			if f.ID == "" {
				continue
			}
			last = f.ID
			created, err := time.Parse(time.RFC3339, f.CreatedAt)
			if err != nil {
				parseFailed = true
			} else if latest == "" || !created.Before(newest) {
				latest, newest = f.ID, created
			}
		}
		if count > 1 {
			notes = append(notes, fmt.Sprintf("%s had %d candidates", name, count))
		}
		if count > 0 && last == "" {
			return nil, nil, fmt.Errorf("no file ID for output %q", name)
		}
		if parseFailed {
			latest = last
		}
		if latest != "" {
			ids[name] = latest
		}
	}
	return ids, notes, nil
}

func (r runner) saveOutput(ctx context.Context, id, path string) error {
	if id == "" {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	return delivery.WriteAtomic(path, func(w io.Writer) error { return r.api.DownloadFile(ctx, id, w) })
}
