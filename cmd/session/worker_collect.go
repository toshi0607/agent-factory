package main

import (
	"bufio"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/toshi0607/agent-factory/internal/cfsandbox"
	"github.com/toshi0607/agent-factory/internal/delivery"
	"github.com/toshi0607/agent-factory/poc/record"
)

const (
	workerAlarmGrace   = 90 * time.Second
	workerStopGrace    = 3 * time.Minute
	workerSettleGrace  = 60 * time.Second
	workerTokenRefresh = 240 * time.Second
	workerLogLimit     = 20 << 20
	workerEventLineMax = 1 << 20
	workerEventsName   = "events.jsonl"
	workerStderrName   = "stderr.log"
	workerEgressName   = "egress.jsonl"
)

func (r runner) collectWorker(ctx context.Context, s state, out string) error {
	start := r.clock.Now()
	client, err := r.workerClient()
	if err != nil {
		return err
	}
	r.worker = client
	if !cfsandbox.ValidRunID(s.WorkID) || s.MinutesLimit < 1 || s.MinutesLimit > workerMaxMinutes || s.StartedAt.IsZero() {
		return fmt.Errorf("state requires a worker run ID, minutes limit between 1 and %d, and start time", workerMaxMinutes)
	}
	if err := os.MkdirAll(out, 0o755); err != nil {
		return err
	}
	status, interruptions, err := r.waitWorker(ctx, s)
	if err != nil {
		return err
	}
	if status.Usage.Inflight != 0 {
		status, err = r.waitWorkerSettlements(ctx, s.WorkID, status)
		if err != nil {
			return err
		}
	}
	switch status.StopReason {
	case stopCompleted, stopBudgetReached, stopTimeLimit, "cancelled", "agent_error", "lost":
	default:
		return errors.New("worker returned an invalid stop reason")
	}
	if status.StartedAt.IsZero() || status.FinishedAt.IsZero() || status.FinishedAt.Before(status.StartedAt) ||
		status.Usage.CostMicrocents < 0 {
		return errors.New("worker returned invalid run timing or cost")
	}

	var notes []string
	outputs, err := r.collectWorkerOutputs(ctx, s.WorkID, out, &notes)
	if err != nil {
		return err
	}
	requiredErr := requiredWorkerOutputs(s.Role, status.StopReason, outputs)
	if requiredErr != nil {
		notes = append(notes, requiredErr.Error())
	} else if s.Role == "fixer" && !outputs[pathsName] {
		notes = append(notes, "changed-paths.txt was not found in worker outputs.")
	}
	patch, notes, err := inspectOutputs(out, outputs[patchName], outputs[pathsName], notes)
	if err != nil {
		return err
	}
	var fetch, search int64
	for _, name := range []string{workerEventsName, workerStderrName} {
		present, err := r.saveWorkerOutput(ctx, s.WorkID, out, name, workerLogLimit, &notes)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if removeErr := removeOutput(filepath.Join(out, name)); removeErr != nil {
				return errors.Join(err, removeErr)
			}
			notes = append(notes, fmt.Sprintf("could not save %s: %v", name, err))
		} else if present && name == workerEventsName {
			fetch, search, err = workerWebTools(filepath.Join(out, name))
			if err != nil {
				return fmt.Errorf("count worker web tools: %w", err)
			}
		}
	}
	var dropped int
	if err := delivery.WriteAtomic(filepath.Join(out, workerEgressName), func(w io.Writer) error {
		var err error
		dropped, err = client.Egress(ctx, s.WorkID, w, -1)
		return err
	}); err != nil {
		return fmt.Errorf("save worker egress log: %w", err)
	}

	usage := status.Usage
	duration := status.FinishedAt.Sub(status.StartedAt).Seconds()
	cents := usage.CostMicrocents / 1_000_000
	if usage.CostMicrocents%1_000_000 != 0 {
		cents++
	}
	notes = append(notes, fmt.Sprintf("Worker version id=%s factory_commit=%s instance=%s cost_microcents=%d",
		cmp.Or(s.WorkerVersion, status.WorkerVersion.ID), cmp.Or(s.WorkerFactoryCommit, status.FactoryCommit),
		status.Container.Instance, usage.CostMicrocents))
	if status.AgentResult != nil && status.AgentResult.TotalCostUSD != nil {
		notes = append(notes, fmt.Sprintf("Agent-reported total_cost_usd=%g", *status.AgentResult.TotalCostUSD))
	}
	if usage.Inflight != 0 {
		notes = append(notes, fmt.Sprintf("inflight=%d", usage.Inflight))
		interruptions.Count++
		interruptions.Notes = append(interruptions.Notes, "Worker usage was still settling after 60 seconds.")
	}
	if usage.LateSettlements != 0 {
		notes = append(notes, fmt.Sprintf("late_settlements=%d", usage.LateSettlements))
	}
	if status.StopReason == stopTimeLimit {
		interruptions.Count++
		interruptions.Notes = append(interruptions.Notes, "Session time limit reached.")
	}
	if status.State == "lost" {
		interruptions.Count++
		interruptions.Notes = append(interruptions.Notes, "Worker lost the run.")
	}
	rec := record.Record{
		SchemaVersion: 1, Candidate: s.Candidate, Task: s.Task, WorkID: s.WorkID,
		BaseCommit: s.BaseCommit, FactoryCommit: s.FactoryCommit, Role: s.Role, Model: s.Model,
		EnvironmentRequestSHA256: s.EnvironmentRequestSHA256, AgentRequestSHA256: s.AgentRequestSHA256,
		BudgetCents: s.BudgetCents, MinutesLimit: s.MinutesLimit, StopReason: status.StopReason,
		StartedAt: status.StartedAt, FinishedAt: status.FinishedAt,
		Session: record.Session{ID: s.WorkID, Status: status.State, DurationSeconds: duration, ActiveSeconds: duration},
		Usage: record.Usage{
			InputTokens: usage.InputTokens, OutputTokens: usage.OutputTokens,
			CacheReadInputTokens:       usage.CacheReadInputTokens,
			CacheCreation5mInputTokens: usage.CacheCreation5mInputTokens,
			CacheCreation1hInputTokens: usage.CacheCreation1hInputTokens,
			ReportedCost:               record.ReportedCost{Amount: strconv.FormatInt(cents, 10), Currency: "USD"},
			WebFetchRequests:           fetch,
			WebSearchRequests:          search,
		},
		RunnerSeconds: record.RunnerSeconds{Collect: r.clock.Now().Sub(start).Seconds()},
		Interruptions: interruptions,
		Egress: record.Egress{
			LogAvailable: true, DeniedDestinations: append([]string{}, status.Egress.DeniedHosts...),
			Notes: fmt.Sprintf("allowed=%d denied=%d llm=%d dropped=%d unmetered_responses=%d",
				status.Egress.Allowed, status.Egress.Denied, status.Egress.LLM, dropped, usage.UnmeteredResponses),
		},
		Patch: patch, Notes: strings.Join(notes, "\n"),
	}
	if err := writeJSON(filepath.Join(out, "record.partial.json"), rec, delivery.WriteAtomic); err != nil {
		return err
	}
	if requiredErr != nil {
		return requiredErr
	}
	return r.cleanup(ctx, s, "", false)
}

func (r runner) waitWorker(ctx context.Context, s state) (cfsandbox.Status, record.Interruptions, error) {
	interruptions := record.Interruptions{Notes: []string{}}
	deadline := s.StartedAt.Add(time.Duration(s.MinutesLimit)*time.Minute + workerAlarmGrace)
	lastToken := s.StartedAt
	if s.WorkerTokenPushedAt != nil {
		lastToken = *s.WorkerTokenPushedAt
	}
	var stopDeadline time.Time
	var stopErr error
	var consecutiveFailures int
	for {
		status, err := r.worker.Status(ctx, s.WorkID)
		if err != nil {
			return status, interruptions, errors.Join(fmt.Errorf("poll worker run: %w", err), stopErr)
		}
		if status.ID != s.WorkID {
			return status, interruptions, errors.New("worker status returned a different run ID")
		}
		switch status.State {
		case "finished", "lost":
			return status, interruptions, nil
		case "created", "running":
		default:
			return status, interruptions, errors.New("worker run is unavailable for collection")
		}

		now := r.clock.Now()
		if stopDeadline.IsZero() && !now.Before(deadline) {
			if status.State != "running" {
				return status, interruptions, errors.New("worker run did not start")
			}
			stopDeadline = now.Add(workerStopGrace)
			stopCtx, cancel := context.WithTimeout(ctx, workerStopGrace)
			defer cancel()
			ctx = stopCtx
			stopErr = r.worker.Stop(ctx, s.WorkID, stopTimeLimit)
			continue
		}
		if !stopDeadline.IsZero() && !now.Before(stopDeadline) {
			return status, interruptions, errors.Join(errors.New("worker run did not finish after the time-limit stop"), stopErr)
		}
		if status.State == "running" && now.Sub(lastToken) >= workerTokenRefresh {
			if err := r.pushWorkerToken(ctx, s.WorkID); err != nil {
				if ctx.Err() != nil {
					return status, interruptions, ctx.Err()
				}
				consecutiveFailures++
				interruptions.Count++
				interruptions.Notes = append(interruptions.Notes, "Worker token refresh failed.")
				if consecutiveFailures == 3 {
					return status, interruptions, errors.Join(
						fmt.Errorf("three consecutive worker token refresh failures: %w", err),
						r.worker.Stop(ctx, s.WorkID, "cancelled"))
				}
			} else {
				lastToken = r.clock.Now()
				consecutiveFailures = 0
			}
		}
		delay := min(r.pollInterval, max(0, cmp.Or(stopDeadline, deadline).Sub(r.clock.Now())))
		if err := r.clock.Sleep(ctx, delay); err != nil {
			return status, interruptions, errors.Join(err, stopErr)
		}
	}
}

func (r runner) waitWorkerSettlements(ctx context.Context, id string, status cfsandbox.Status) (cfsandbox.Status, error) {
	waitCtx, cancel := context.WithTimeout(ctx, workerSettleGrace)
	defer cancel()
	deadline := r.clock.Now().Add(workerSettleGrace)
	for status.Usage.Inflight != 0 {
		delay := min(r.pollInterval, max(0, deadline.Sub(r.clock.Now())))
		if err := r.clock.Sleep(waitCtx, delay); err != nil {
			if waitCtx.Err() != nil {
				break
			}
			return status, err
		}
		if !r.clock.Now().Before(deadline) {
			break
		}
		next, err := r.worker.Status(waitCtx, id)
		if waitCtx.Err() != nil {
			break
		}
		if err != nil {
			return status, fmt.Errorf("poll worker settlements: %w", err)
		}
		if next.ID != id {
			return status, errors.New("worker status returned a different run ID")
		}
		if next.State != "finished" && next.State != "lost" {
			return status, errors.New("worker run is unavailable for collection")
		}
		status = next
	}
	return status, ctx.Err()
}

func (r runner) collectWorkerOutputs(ctx context.Context, id, out string, notes *[]string) (map[string]bool, error) {
	present := make(map[string]bool, 3)
	for _, name := range []string{patchName, pathsName, probeName} {
		found, err := r.saveWorkerOutput(ctx, id, out, name, -1, notes)
		if err != nil {
			return nil, fmt.Errorf("save %s: %w", name, err)
		}
		present[name] = found
	}
	return present, nil
}

func requiredWorkerOutputs(role, reason string, present map[string]bool) error {
	var required []string
	switch {
	case role == "probe":
		required = []string{probeName}
	case role == "fixer" && reason == stopCompleted:
		required = []string{patchName, pathsName}
	}
	var errs []error
	for _, name := range required {
		if !present[name] {
			errs = append(errs, fmt.Errorf("worker output %s is required for the %s role", name, role))
		}
	}
	return errors.Join(errs...)
}

func (r runner) saveWorkerOutput(ctx context.Context, id, out, name string, maxBytes int64, notes *[]string) (bool, error) {
	path := filepath.Join(out, name)
	var truncated bool
	err := delivery.WriteAtomic(path, func(w io.Writer) error {
		var err error
		truncated, err = r.worker.Output(ctx, id, name, w, maxBytes)
		return err
	})
	if cfsandbox.IsNotFound(err) {
		return false, removeOutput(path)
	}
	if err == nil && truncated {
		*notes = append(*notes, fmt.Sprintf("%s was truncated.", name))
	}
	return err == nil, err
}

func workerWebTools(path string) (fetch, search int64, err error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()
	reader := bufio.NewReaderSize(f, workerEventLineMax)
	var oversized bool
	type block struct {
		Type string `json:"type"`
		Name string `json:"name"`
	}
	count := func(b block) {
		if b.Type == "tool_use" {
			switch b.Name {
			case "WebFetch":
				fetch++
			case "WebSearch":
				search++
			}
		}
	}
	for {
		line, readErr := reader.ReadSlice('\n')
		if readErr == bufio.ErrBufferFull {
			oversized = true
			continue
		}
		if readErr != nil && readErr != io.EOF {
			return 0, 0, readErr
		}
		if !oversized {
			var event struct {
				block
				Message struct {
					Content []block `json:"content"`
				} `json:"message"`
			}
			if json.Unmarshal(line, &event) == nil {
				count(event.block)
				if event.Type == "assistant" {
					for _, b := range event.Message.Content {
						count(b)
					}
				}
			}
		}
		if readErr == io.EOF {
			return fetch, search, nil
		}
		oversized = false
	}
}
