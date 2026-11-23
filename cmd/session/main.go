package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"syscall"
	"time"

	"github.com/toshi0607/agent-factory/internal/claude"
	"github.com/toshi0607/agent-factory/internal/claudeauth"
	"github.com/toshi0607/agent-factory/internal/delivery"
)

type clock interface {
	Now() time.Time
	Sleep(context.Context, time.Duration) error
}

type wallClock struct{}

func (wallClock) Now() time.Time { return time.Now() }

func (wallClock) Sleep(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

type runner struct {
	api          *claude.Client
	auth         *claudeauth.Federation
	clock        clock
	pollInterval time.Duration
	stdout       io.Writer
}

var messagesModelPattern = regexp.MustCompile(`^claude-[a-z0-9-]{1,60}$`)

type state struct {
	WorkID                   string    `json:"work_id"`
	Candidate                string    `json:"candidate"`
	Task                     string    `json:"task"`
	BaseCommit               string    `json:"base_commit"`
	FactoryCommit            string    `json:"factory_commit"`
	Model                    string    `json:"model"`
	Role                     string    `json:"role"`
	EnvironmentID            string    `json:"environment_id"`
	AgentID                  string    `json:"agent_id"`
	UploadedFileIDs          []string  `json:"uploaded_file_ids"`
	SessionID                string    `json:"session_id"`
	BudgetCents              int       `json:"budget_cents"`
	MinutesLimit             int       `json:"minutes_limit"`
	StartedAt                time.Time `json:"started_at"`
	EnvironmentRequestSHA256 string    `json:"environment_request_sha256"`
	AgentRequestSHA256       string    `json:"agent_request_sha256"`
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	auth := claudeauth.NewFederation(claude.DefaultBaseURL, http.DefaultClient, claudeauth.ConfigFromEnv())
	r := runner{
		api: claude.New(claude.DefaultBaseURL, http.DefaultClient, auth), auth: auth,
		clock: wallClock{}, pollInterval: 10 * time.Second, stdout: os.Stdout,
	}
	if err := r.run(ctx, os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "session:", err)
		os.Exit(1)
	}
}

func (r runner) run(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: session <auth-check|oidc-claims|start|collect|cleanup|merge>")
	}
	command, args := args[0], args[1:]
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	switch command {
	case "auth-check":
		hold := flags.Duration("hold", 0, "wait before checking token refresh (maximum 20 minutes)")
		model := flags.String("messages", "", "model for one Messages API request")
		if err := parseFlags(flags, args); err != nil {
			return err
		}
		if *hold < 0 || *hold > 20*time.Minute {
			return errors.New("-hold must be between 0 and 20 minutes")
		}
		var holdSet, messagesSet bool
		flags.Visit(func(f *flag.Flag) {
			holdSet = holdSet || f.Name == "hold"
			messagesSet = messagesSet || f.Name == "messages"
		})
		if messagesSet {
			if holdSet {
				return errors.New("-messages and -hold cannot be combined")
			}
			if !messagesModelPattern.MatchString(*model) {
				return errors.New("-messages model must match " + messagesModelPattern.String())
			}
		}
		if err := r.authCheck(ctx, *hold); err != nil || !messagesSet {
			return err
		}
		check, err := r.api.CheckMessages(ctx, *model)
		if check.HTTPStatus == 0 {
			return err
		}
		return errors.Join(err, json.NewEncoder(r.stdout).Encode(check))
	case "oidc-claims":
		if err := parseFlags(flags, args); err != nil {
			return err
		}
		claims, err := r.auth.OIDCClaims(ctx)
		if err != nil {
			return err
		}
		return json.NewEncoder(r.stdout).Encode(claims)
	case "start":
		cfg := flags.String("policy", "", "policy file")
		role := flags.String("role", "fixer", "policy role")
		candidate := flags.String("candidate", "managed-agents", "candidate name")
		files := flags.String("files", "", "prepare output directory")
		statePath := flags.String("state", "", "new state file")
		budget := flags.Int("budget-cents", 0, "lower the role's LLM budget in USD cents")
		minutes := flags.Int("minutes", 0, "lower the role's time limit in minutes (maximum 45)")
		if err := parseFlags(flags, args, cfg, role, candidate, files, statePath); err != nil {
			return err
		}
		var overrideErr error
		flags.Visit(func(override *flag.Flag) {
			switch {
			case override.Name == "budget-cents" && *budget <= 0:
				overrideErr = errors.Join(overrideErr, errors.New("-budget-cents must be positive"))
			case override.Name == "minutes" && *minutes <= 0:
				overrideErr = errors.Join(overrideErr, errors.New("-minutes must be positive"))
			}
		})
		if overrideErr != nil {
			return overrideErr
		}
		return r.start(ctx, *cfg, *role, *candidate, *files, *statePath, *budget, *minutes)
	case "collect":
		statePath := flags.String("state", "", "state file")
		out := flags.String("out", "", "collection output directory")
		if err := parseFlags(flags, args, statePath, out); err != nil {
			return err
		}
		s, err := readJSON[state](*statePath)
		if err != nil {
			return fmt.Errorf("could not read session state: %w; %s", err, recoveryHint)
		}
		return r.collect(ctx, s, *out)
	case "cleanup":
		statePath := flags.String("state", "", "state file")
		if err := parseFlags(flags, args, statePath); err != nil {
			return err
		}
		s, err := readJSON[state](*statePath)
		if err != nil {
			return err
		}
		return r.cleanup(ctx, s, "", false)
	case "merge":
		partial := flags.String("record", "", "partial record")
		check := flags.String("check", "", "check result")
		start := flags.String("runner-start", "", "start runner seconds")
		checkTime := flags.String("runner-check", "", "check runner seconds")
		out := flags.String("out", "", "final record file")
		if err := parseFlags(flags, args, partial, check, start, checkTime, out); err != nil {
			return err
		}
		return merge(*partial, *check, *start, *checkTime, *out)
	default:
		return fmt.Errorf("unknown subcommand %q", command)
	}
}

func parseFlags(f *flag.FlagSet, args []string, required ...*string) error {
	if err := f.Parse(args); err != nil {
		return err
	}
	if f.NArg() != 0 {
		return fmt.Errorf("%s: unexpected positional arguments", f.Name())
	}
	for _, value := range required {
		if *value == "" {
			return fmt.Errorf("%s: required flag missing", f.Name())
		}
	}
	return nil
}

func (r runner) authCheck(ctx context.Context, hold time.Duration) error {
	status, firstExchanges, err := r.authCheckOnce(ctx, hold > 0)
	if hold == 0 || err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("first auth check returned HTTP status %d, want 200", status)
	}
	if err := r.clock.Sleep(ctx, hold); err != nil {
		return fmt.Errorf("wait before second auth check: %w", err)
	}
	status, exchanges, err := r.authCheckOnce(ctx, true)
	if exchanges <= firstExchanges {
		err = errors.Join(err, fmt.Errorf("federated token was not re-exchanged (exchanges: %d -> %d)", firstExchanges, exchanges))
	}
	if status != http.StatusOK {
		err = errors.Join(err, fmt.Errorf("second auth check returned HTTP status %d, want 200", status))
	}
	return err
}

func (r runner) authCheckOnce(ctx context.Context, includeExchanges bool) (int, int, error) {
	status, err := r.api.CheckAgents(ctx)
	info, ok := r.auth.Info()
	if !ok && !includeExchanges {
		return status, 0, err
	}
	result := struct {
		claudeauth.TokenInfo
		HTTPStatus int  `json:"http_status"`
		Exchanges  *int `json:"exchanges,omitempty"`
	}{TokenInfo: info, HTTPStatus: status}
	if includeExchanges {
		result.Exchanges = new(info.Exchanges)
	}
	printErr := json.NewEncoder(r.stdout).Encode(result)
	return status, info.Exchanges, errors.Join(err, printErr)
}

func readJSON[T any](path string) (T, error) {
	var value T
	data, err := os.ReadFile(path)
	if err != nil {
		return value, err
	}
	if err := json.Unmarshal(data, &value); err != nil {
		return value, fmt.Errorf("decode %s: %w", path, err)
	}
	return value, nil
}

func writeJSON(path string, value any, publish func(string, func(io.Writer) error) error) error {
	return publish(path, func(w io.Writer) error {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(value)
	})
}

func writeBytes(path string, data []byte) error {
	return delivery.WriteAtomic(path, func(w io.Writer) error {
		_, err := w.Write(data)
		return err
	})
}
