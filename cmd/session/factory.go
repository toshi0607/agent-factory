package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/toshi0607/agent-factory/internal/factorystate"
)

const (
	exitStateError = 2
	exitStopped    = 3
	exitInProgress = 4
	stopStopped    = "stopped"
	workerCancel   = "cancelled"
	stoppedNote    = "Factory stop flag was set."
)

// factoryState is the shared stop flag and in-progress record. A nil value
// means state is not configured and no stage consults it.
type factoryState interface {
	Stopped(context.Context) (*factorystate.StopFlag, error)
	Stop(ctx context.Context, reason, setBy, workID string) (bool, error)
	Begin(context.Context, factorystate.InProgress) (*factorystate.InProgress, error)
	Update(context.Context, factorystate.InProgress, int64) error
	Current(context.Context) (*factorystate.InProgress, int64, error)
	End(context.Context, string) error
}

type exitError struct {
	code int
	err  error
}

func (e *exitError) Error() string { return e.err.Error() }
func (e *exitError) Unwrap() error { return e.err }

func exitCode(err error) int {
	if exitErr, ok := errors.AsType[*exitError](err); ok {
		return exitErr.code
	}
	return 1
}

var errFactoryStopped = &exitError{exitStopped, errors.New("factory is stopped")}

// stopRequested reports whether the stop flag is set. A failed check is an
// exit-code-2 error, which callers treat as "do not proceed".
func (r runner) stopRequested(ctx context.Context) (bool, error) {
	if r.factory == nil {
		return false, nil
	}
	flag, err := r.factory.Stopped(ctx)
	if err != nil {
		return false, &exitError{exitStateError, fmt.Errorf("check the factory stop flag: %w", err)}
	}
	return flag != nil, nil
}

const (
	stopCheckInterval    = 30 * time.Second
	stopCheckMaxFailures = 3
	stopCheckFailedNote  = "A factory stop flag check failed while waiting for the session."
)

// stopWatch throttles stop-flag checks while collect waits for a running
// session.
type stopWatch struct {
	checked   bool
	lastCheck time.Time
	failures  int
	failed    bool
}

// pollStop checks the stop flag on the first call and then at most once per
// stopCheckInterval. Only stopCheckMaxFailures consecutive failed checks are
// an error; that error is the one the start-of-collect check returns.
func (r runner) pollStop(ctx context.Context, w *stopWatch) (bool, error) {
	if r.factory == nil {
		return false, nil
	}
	now := r.clock.Now()
	if w.checked && now.Sub(w.lastCheck) < stopCheckInterval {
		return false, nil
	}
	w.checked, w.lastCheck = true, now
	stopped, err := r.stopRequested(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		w.failures++
		w.failed = true
		if w.failures >= stopCheckMaxFailures {
			return false, err
		}
		return false, nil
	}
	w.failures = 0
	return stopped, nil
}

func (r runner) checkNotStopped(ctx context.Context) error {
	stopped, err := r.stopRequested(ctx)
	if err == nil && stopped {
		return errFactoryStopped
	}
	return err
}

func (r runner) beginUnit(ctx context.Context, s state) error {
	if r.factory == nil {
		return nil
	}
	existing, err := r.factory.Begin(ctx, factorystate.InProgress{
		WorkID: s.WorkID, Role: s.Role, Task: s.Task, BaseCommit: s.BaseCommit, Candidate: s.Candidate,
		BudgetCents: s.BudgetCents, MinutesLimit: s.MinutesLimit, StartedAt: r.clock.Now().UTC(),
		RunID: os.Getenv("GITHUB_RUN_ID"), RunAttempt: os.Getenv("GITHUB_RUN_ATTEMPT"),
	})
	if err != nil {
		return &exitError{exitStateError, fmt.Errorf("record the in-progress unit: %w", err)}
	}
	if existing != nil {
		id := existing.WorkID
		if !factorystate.ValidWorkID(id) {
			id = "<invalid work ID>"
		}
		return &exitError{exitInProgress, fmt.Errorf("another unit is in progress: %s", id)}
	}
	return nil
}

// recordSession adds the session ID to this unit's in-progress record.
func (r runner) recordSession(ctx context.Context, s state) error {
	if r.factory == nil {
		return nil
	}
	current, generation, err := r.factory.Current(ctx)
	if err != nil {
		return fmt.Errorf("read the in-progress record: %w", err)
	}
	if current == nil || current.WorkID != s.WorkID {
		return errors.New("the in-progress record no longer belongs to this unit")
	}
	current.SessionID, current.StartedAt = s.SessionID, s.StartedAt.UTC()
	if err := r.factory.Update(ctx, *current, generation); err != nil {
		return fmt.Errorf("update the in-progress record: %w", err)
	}
	return nil
}

func (r runner) endUnit(ctx context.Context, workID string) error {
	if r.factory == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Minute)
	defer cancel()
	if err := r.factory.End(ctx, workID); err != nil {
		return fmt.Errorf("end the in-progress record: %w", err)
	}
	return nil
}

func (r runner) stateCommand(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return &exitError{exitStateError, errors.New("usage: session state <check|stop>")}
	}
	if r.factory == nil {
		return &exitError{exitStateError, fmt.Errorf("factory state is not configured; set %s, %s, and %s",
			factorystate.EnvProvider, factorystate.EnvServiceAccount, factorystate.EnvBucket)}
	}
	command, args := args[0], args[1:]
	flags := flag.NewFlagSet("state "+command, flag.ContinueOnError)
	switch command {
	case "check":
		if err := parseFlags(flags, args); err != nil {
			return &exitError{exitStateError, err}
		}
		set, err := r.factory.Stopped(ctx)
		if err != nil {
			return &exitError{exitStateError, fmt.Errorf("check the factory stop flag: %w", err)}
		}
		if set == nil {
			return json.NewEncoder(r.stdout).Encode(struct {
				Stopped bool `json:"stopped"`
			}{})
		}
		return errors.Join(errFactoryStopped, json.NewEncoder(r.stdout).Encode(struct {
			Stopped bool `json:"stopped"`
			factorystate.StopFlag
		}{true, *set}))
	case "stop":
		reason := flags.String("reason", "", "single-line reason (at most 200 characters)")
		stage := flags.String("stage", "", "stage that sets the flag")
		workID := flags.String("work-id", "", "work ID the stop relates to")
		if err := parseFlags(flags, args, reason, stage); err != nil {
			return &exitError{exitStateError, err}
		}
		already, err := r.factory.Stop(ctx, *reason, *stage, *workID)
		if err != nil {
			return &exitError{exitStateError, fmt.Errorf("set the factory stop flag: %w", err)}
		}
		return json.NewEncoder(r.stdout).Encode(struct {
			Stopped    bool `json:"stopped"`
			AlreadySet bool `json:"already_set"`
		}{true, already})
	default:
		return &exitError{exitStateError, fmt.Errorf("unknown state subcommand %q", command)}
	}
}
