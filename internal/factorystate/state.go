package factorystate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/toshi0607/agent-factory/internal/claudeauth"
)

const (
	stopObject       = "stop/flag.json"
	inProgressObject = "in-progress/current.json"
	maxReasonRunes   = 200
)

var (
	stagePattern  = regexp.MustCompile(`^[a-z][a-z0-9-]{0,40}$`)
	workIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,100}$`)
)

// ValidWorkID reports whether id is safe to print and store.
func ValidWorkID(id string) bool { return workIDPattern.MatchString(id) }

type StopFlag struct {
	Reason string    `json:"reason"`
	SetBy  string    `json:"set_by"`
	WorkID string    `json:"work_id"`
	SetAt  time.Time `json:"set_at"`
}

type InProgress struct {
	WorkID       string    `json:"work_id"`
	Role         string    `json:"role"`
	Task         string    `json:"task"`
	BaseCommit   string    `json:"base_commit"`
	Candidate    string    `json:"candidate"`
	SessionID    string    `json:"session_id"`
	BudgetCents  int       `json:"budget_cents"`
	MinutesLimit int       `json:"minutes_limit"`
	StartedAt    time.Time `json:"started_at"`
	RunID        string    `json:"run_id"`
	RunAttempt   string    `json:"run_attempt"`
}

// Store reads and writes the shared state. The stop flag can only be
// created: no method replaces or deletes it.
type Store struct {
	objects *objects
	now     func() time.Time
}

// New builds a store. oidcHTTP is used only for the GitHub Actions OIDC
// request; every Google request goes through the host allowlist.
func New(cfg Config, oidcHTTP *http.Client, oidc claudeauth.Config) (*Store, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if oidcHTTP == nil {
		oidcHTTP = http.DefaultClient
	}
	google := newGoogleHTTP(oidcHTTP)
	tokens := newTokenSource(cfg, google, oidcHTTP, oidc)
	return &Store{objects: &objects{google: google, tokens: tokens, bucket: cfg.Bucket}, now: time.Now}, nil
}

// Stopped returns the stop flag, or nil when the factory is not stopped.
// A flag that cannot be read or decoded is an error; callers must not proceed.
func (s *Store) Stopped(ctx context.Context) (*StopFlag, error) {
	data, _, found, err := s.objects.Get(ctx, stopObject)
	if err != nil || !found {
		return nil, err
	}
	var flag StopFlag
	if err := decodeObject(data, &flag); err != nil {
		return nil, errors.New("the stop flag exists but is malformed; treat the factory as stopped")
	}
	return &flag, nil
}

// Stop creates the stop flag. An existing flag is kept as it is.
func (s *Store) Stop(ctx context.Context, reason, setBy, workID string) (bool, error) {
	if reason == "" || utf8.RuneCountInString(reason) > maxReasonRunes || !utf8.ValidString(reason) ||
		containsControl(reason) {
		return false, fmt.Errorf("stop reason must be a single line of 1 to %d characters", maxReasonRunes)
	}
	if !stagePattern.MatchString(setBy) {
		return false, errors.New("stop stage must match " + stagePattern.String())
	}
	if workID != "" && !ValidWorkID(workID) {
		return false, errors.New("stop work ID must match " + workIDPattern.String())
	}
	data, err := json.Marshal(StopFlag{Reason: reason, SetBy: setBy, WorkID: workID, SetAt: s.now().UTC().Truncate(time.Second)})
	if err != nil {
		return false, errors.New("could not encode the stop flag")
	}
	created, err := s.objects.Create(ctx, stopObject, data)
	return !created && err == nil, err
}

// Begin creates the in-progress record. When a record already exists it is
// returned and nothing is written.
func (s *Store) Begin(ctx context.Context, rec InProgress) (*InProgress, error) {
	data, err := encodeRecord(rec)
	if err != nil {
		return nil, err
	}
	created, err := s.objects.Create(ctx, inProgressObject, data)
	if err != nil || created {
		return nil, err
	}
	existing, _, err := s.Current(ctx)
	if err != nil {
		return nil, err
	}
	if existing == nil {
		return nil, errors.New("the in-progress record changed while it was read; retry")
	}
	return existing, nil
}

// Update replaces the record only if it still has the given generation.
func (s *Store) Update(ctx context.Context, rec InProgress, generation int64) error {
	data, err := encodeRecord(rec)
	if err != nil {
		return err
	}
	return s.objects.Replace(ctx, inProgressObject, data, generation)
}

// Current returns the in-progress record and its generation, or nil.
func (s *Store) Current(ctx context.Context) (*InProgress, int64, error) {
	data, generation, found, err := s.objects.Get(ctx, inProgressObject)
	if err != nil || !found {
		return nil, 0, err
	}
	var rec InProgress
	if err := decodeObject(data, &rec); err != nil || !ValidWorkID(rec.WorkID) {
		return nil, 0, errors.New("the in-progress record is malformed")
	}
	return &rec, generation, nil
}

// End deletes the record only if it belongs to workID. A missing record or
// one for another unit is left alone.
func (s *Store) End(ctx context.Context, workID string) error {
	rec, generation, err := s.Current(ctx)
	if err != nil || rec == nil || rec.WorkID != workID {
		return err
	}
	return s.objects.Delete(ctx, inProgressObject, generation)
}

func encodeRecord(rec InProgress) ([]byte, error) {
	if !ValidWorkID(rec.WorkID) {
		return nil, errors.New("in-progress record needs a valid work ID")
	}
	data, err := json.Marshal(rec)
	if err != nil {
		return nil, errors.New("could not encode the in-progress record")
	}
	return data, nil
}

func decodeObject(data []byte, v any) error {
	if !bytes.HasPrefix(bytes.TrimSpace(data), []byte("{")) {
		return errors.New("not a JSON object")
	}
	return json.Unmarshal(data, v)
}

func containsControl(s string) bool {
	for _, r := range s {
		if unicode.IsControl(r) || r == ' ' || r == ' ' {
			return true
		}
	}
	return false
}
