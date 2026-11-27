package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/toshi0607/agent-factory/internal/delivery"
	"github.com/toshi0607/agent-factory/internal/factorystate"
	"github.com/toshi0607/agent-factory/poc/record"
)

type fakeFactory struct {
	stop       *factorystate.StopFlag
	stoppedErr error
	// stoppedErrs, when set, gives the error of each Stopped call in order;
	// later calls fall back to stoppedErr.
	stoppedErrs  []error
	stoppedCalls int
	record       *factorystate.InProgress
	generation   int64
	calls        []string
}

func (f *fakeFactory) Stopped(context.Context) (*factorystate.StopFlag, error) {
	f.calls = append(f.calls, "Stopped")
	err := f.stoppedErr
	if f.stoppedCalls < len(f.stoppedErrs) {
		err = f.stoppedErrs[f.stoppedCalls]
	}
	f.stoppedCalls++
	return f.stop, err
}

func (f *fakeFactory) Stop(_ context.Context, reason, setBy, workID string) (bool, error) {
	f.calls = append(f.calls, "Stop")
	if f.stop != nil {
		return true, nil
	}
	f.stop = &factorystate.StopFlag{Reason: reason, SetBy: setBy, WorkID: workID}
	return false, nil
}

func (f *fakeFactory) Begin(_ context.Context, rec factorystate.InProgress) (*factorystate.InProgress, error) {
	f.calls = append(f.calls, "Begin")
	if f.record != nil {
		existing := *f.record
		return &existing, nil
	}
	f.record, f.generation = &rec, f.generation+1
	return nil, nil
}

func (f *fakeFactory) Update(_ context.Context, rec factorystate.InProgress, generation int64) error {
	f.calls = append(f.calls, "Update")
	if f.record == nil || generation != f.generation {
		return errors.New("changed since read")
	}
	f.record, f.generation = &rec, f.generation+1
	return nil
}

func (f *fakeFactory) Current(context.Context) (*factorystate.InProgress, int64, error) {
	f.calls = append(f.calls, "Current")
	if f.record == nil {
		return nil, 0, nil
	}
	current := *f.record
	return &current, f.generation, nil
}

func (f *fakeFactory) End(_ context.Context, workID string) error {
	f.calls = append(f.calls, "End")
	if f.record != nil && f.record.WorkID == workID {
		f.record = nil
	}
	return nil
}

func noAPI(t *testing.T) func(*http.Request) (int, string) {
	return func(req *http.Request) (int, string) {
		t.Errorf("unexpected API call %s %s", req.Method, req.URL.Path)
		return 500, ""
	}
}

func TestStartRefusesWhenStoppedOrInProgress(t *testing.T) {
	t.Chdir("../..")
	cfg, dir, _ := preparedFiles(t)
	for _, tc := range []struct {
		name      string
		factory   *fakeFactory
		candidate string
		code      int
		want      string
		calls     []string
	}{
		{"stopped", &fakeFactory{stop: &factorystate.StopFlag{Reason: "test"}}, "managed-agents", exitStopped,
			"factory is stopped", []string{"Stopped"}},
		{"stop check fails", &fakeFactory{stoppedErr: errors.New("storage unavailable")}, "managed-agents", exitStateError,
			"storage unavailable", []string{"Stopped"}},
		{"in progress", &fakeFactory{record: &factorystate.InProgress{WorkID: "p0-20261119T000000Z-00000001", Task: "secret task"}},
			"managed-agents", exitInProgress, "another unit is in progress: p0-20261119T000000Z-00000001", []string{"Stopped", "Begin"}},
		{"worker in progress", &fakeFactory{record: &factorystate.InProgress{WorkID: "p0-20261119T000000Z-00000001"}},
			workerCandidate, exitInProgress, "another unit is in progress", []string{"Stopped", "Begin"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			statePath := filepath.Join(t.TempDir(), "state.json")
			r := testRunner(noAPI(t), testClock())
			if tc.candidate == workerCandidate {
				r = workerTestRunner(t, testClock(), func(w http.ResponseWriter, req *http.Request) {
					t.Errorf("unexpected worker call %s %s", req.Method, req.URL.Path)
				})
			}
			r.factory = tc.factory
			err := r.run(t.Context(), []string{"start", "-policy", cfg, "-candidate", tc.candidate, "-files", dir, "-state", statePath})
			if exitCode(err) != tc.code || err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("start = %v (exit %d), want exit %d with %q", err, exitCode(err), tc.code, tc.want)
			}
			if strings.Contains(err.Error(), "secret task") {
				t.Fatal("refusal printed more than the work ID")
			}
			if !slices.Equal(tc.factory.calls, tc.calls) {
				t.Fatalf("state calls = %v, want %v", tc.factory.calls, tc.calls)
			}
			if _, err := os.Stat(statePath); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("start left a state file: %v", err)
			}
		})
	}
}

func startHandler(t *testing.T, factory *fakeFactory, failMessage bool, cleanup *[]string) func(*http.Request) (int, string) {
	return func(req *http.Request) (int, string) {
		switch req.Method + " " + req.URL.RequestURI() {
		case "POST /v1/environments":
			if factory.record == nil || factory.record.SessionID != "" {
				t.Error("environment created before the in-progress record")
			}
			return 200, `{"id":"env-1"}`
		case "POST /v1/agents":
			return 200, `{"id":"agent-1","tools":[{"type":"agent_toolset_20260401","default_config":{"enabled":false}}]}`
		case "POST /v1/files":
			return 200, `{"id":"file-1"}`
		case "POST /v1/sessions":
			var body struct{ Resources []map[string]any }
			decode(t, readRequest(t, req), &body)
			for _, res := range body.Resources {
				res["mount_path"] = "/mnt/session/uploads" + res["mount_path"].(string)
			}
			resources, err := json.Marshal(body.Resources)
			if err != nil {
				t.Fatal(err)
			}
			return 200, `{"id":"session-1","resources":` + string(resources) + `}`
		case "POST /v1/sessions/session-1/events?beta=true":
			if factory.record == nil || factory.record.SessionID != "session-1" {
				t.Error("user message sent before the record named the session")
			}
			if failMessage {
				return 400, "rejected"
			}
			return 200, "{}"
		case "GET /v1/sessions/session-1":
			return 200, `{"status":"idle"}`
		default:
			*cleanup = append(*cleanup, req.Method+" "+req.URL.Path)
			return 200, "{}"
		}
	}
}

func TestStartRecordsInProgressUnit(t *testing.T) {
	t.Setenv("FACTORY_COMMIT", factoryCommit)
	t.Setenv("GITHUB_RUN_ID", "1234")
	t.Setenv("GITHUB_RUN_ATTEMPT", "2")
	t.Chdir("../..")
	cfg, dir, m := preparedFiles(t)
	for _, fail := range []bool{false, true} {
		t.Run(fmt.Sprintf("fail=%v", fail), func(t *testing.T) {
			statePath := filepath.Join(t.TempDir(), "state.json")
			factory := &fakeFactory{}
			var cleanup []string
			clock := testClock()
			r := testRunner(startHandler(t, factory, fail, &cleanup), clock)
			r.factory = factory
			err := r.run(t.Context(), []string{"start", "-policy", cfg, "-files", dir, "-state", statePath})
			s, readErr := readJSON[state](statePath)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if fail {
				if err == nil || exitCode(err) != 1 {
					t.Fatalf("start = %v, want a plain failure", err)
				}
				if !slices.Equal(factory.calls, []string{"Stopped", "Begin", "Current", "Update", "End"}) || factory.record != nil {
					t.Fatalf("state calls = %v, record = %+v; want the record ended", factory.calls, factory.record)
				}
				if !slices.Contains(cleanup, "DELETE /v1/sessions/session-1") {
					t.Fatalf("cleanup = %v", cleanup)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(factory.calls, []string{"Stopped", "Begin", "Current", "Update"}) {
				t.Fatalf("state calls = %v", factory.calls)
			}
			want := factorystate.InProgress{
				WorkID: s.WorkID, Role: "fixer", Task: m.Task, BaseCommit: m.BaseCommit, Candidate: "managed-agents",
				SessionID: "session-1", BudgetCents: 300, MinutesLimit: 30, StartedAt: clock.Now(), RunID: "1234", RunAttempt: "2",
			}
			if factory.record == nil || *factory.record != want {
				t.Fatalf("record = %+v, want %+v", factory.record, want)
			}
		})
	}
}

func collectHandler(t *testing.T, out string, statuses []string, interrupts, gets *int, cleanup *[]string) func(*http.Request) (int, string) {
	return func(req *http.Request) (int, string) {
		switch req.Method + " " + req.URL.RequestURI() {
		case "GET /v1/sessions/session-1":
			status := statuses[min(*gets, len(statuses)-1)]
			*gets++
			return 200, status
		case "POST /v1/sessions/session-1/events?beta=true":
			*interrupts++
			return 200, "{}"
		case "GET /v1/sessions/session-1/events?beta=true":
			return 200, `{"data":[]}`
		case "GET /v1/files?scope_id=session-1":
			return 200, `{"data":[{"id":"patch","filename":"outputs/patch.diff"},{"id":"paths","filename":"outputs/changed-paths.txt"}]}`
		case "GET /v1/files/patch/content":
			return 200, "patch\n"
		case "GET /v1/files/paths/content":
			return 200, "a.go\n"
		default:
			if _, err := os.Stat(filepath.Join(out, "record.partial.json")); err != nil {
				t.Errorf("cleanup before the record was saved: %v", err)
			}
			*cleanup = append(*cleanup, req.Method+" "+req.URL.Path)
			return 200, "{}"
		}
	}
}

func TestCollectHonoursStateHooks(t *testing.T) {
	const running = `{"status":"running"}`
	const done = `{"status":"idle","usage":{"active_seconds":3}}`
	wantCleanup := []string{"DELETE /v1/sessions/session-1", "POST /v1/agents/agent-1/archive",
		"DELETE /v1/environments/env-1", "DELETE /v1/files/upload-1", "DELETE /v1/files/upload-2"}
	for _, tc := range []struct {
		name       string
		stopped    bool
		statuses   []string
		code       int
		reason     string
		interrupts int
	}{
		{"completed", false, []string{done}, 0, stopCompleted, 0},
		{"stopped", true, []string{running, done}, exitStopped, stopStopped, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clock := testClock()
			s := sessionState(clock.Now())
			s.MinutesLimit = 30
			factory := &fakeFactory{record: &factorystate.InProgress{WorkID: s.WorkID, SessionID: s.SessionID}, generation: 3}
			if tc.stopped {
				factory.stop = &factorystate.StopFlag{Reason: "test"}
			}
			out := t.TempDir()
			var interrupts, gets int
			var cleanup []string
			r := testRunner(collectHandler(t, out, tc.statuses, &interrupts, &gets, &cleanup), clock)
			r.factory = factory
			err := r.collect(t.Context(), s, out)
			if exitCode(err) != tc.code && !(tc.code == 0 && err == nil) {
				t.Fatalf("collect = %v (exit %d), want exit %d", err, exitCode(err), tc.code)
			}
			if tc.code == 0 && err != nil {
				t.Fatal(err)
			}
			rec, readErr := readJSON[record.Record](filepath.Join(out, "record.partial.json"))
			if readErr != nil || rec.Validate() != nil || rec.StopReason != tc.reason || interrupts != tc.interrupts ||
				rec.Interruptions.Count != tc.interrupts {
				t.Fatalf("record = %+v, %v; interrupts = %d", rec, readErr, interrupts)
			}
			if tc.stopped && !slices.Equal(rec.Interruptions.Notes, []string{stoppedNote}) {
				t.Fatalf("interruption notes = %v", rec.Interruptions.Notes)
			}
			if !slices.Equal(cleanup, wantCleanup) || factory.record != nil ||
				!slices.Equal(factory.calls, []string{"Stopped", "End"}) {
				t.Fatalf("cleanup = %v, state calls = %v, record = %+v", cleanup, factory.calls, factory.record)
			}
		})
	}
}

func TestCollectStopCheckFailureStopsSession(t *testing.T) {
	clock := testClock()
	s := sessionState(clock.Now())
	factory := &fakeFactory{stoppedErr: errors.New("storage unavailable"),
		record: &factorystate.InProgress{WorkID: s.WorkID}, generation: 1}
	var calls []string
	r := testRunner(func(req *http.Request) (int, string) {
		calls = append(calls, req.Method+" "+req.URL.Path)
		if req.Method == http.MethodGet && req.URL.Path == "/v1/sessions/session-1" {
			return 200, `{"status":"idle"}`
		}
		return 200, "{}"
	}, clock)
	r.factory = factory
	err := r.collect(t.Context(), s, t.TempDir())
	if exitCode(err) != exitStateError || !strings.Contains(err.Error(), "storage unavailable") ||
		!strings.Contains(err.Error(), "resources were kept") {
		t.Fatalf("collect = %v (exit %d)", err, exitCode(err))
	}
	if !slices.Equal(calls, []string{"GET /v1/sessions/session-1"}) || factory.record == nil {
		t.Fatalf("calls = %v, record = %+v; want a settled session kept for recovery", calls, factory.record)
	}
}

func TestCollectRechecksStopFlagWhileWaiting(t *testing.T) {
	const running = `{"status":"running"}`
	const done = `{"status":"idle","usage":{"active_seconds":3}}`
	storageErr := errors.New("storage unavailable")
	wantCleanup := []string{"DELETE /v1/sessions/session-1", "POST /v1/agents/agent-1/archive",
		"DELETE /v1/environments/env-1", "DELETE /v1/files/upload-1", "DELETE /v1/files/upload-2"}
	statuses := func(runningPolls int) []string { return append(slices.Repeat([]string{running}, runningPolls), done) }
	stopped := func(n int) []string { return slices.Repeat([]string{"Stopped"}, n) }
	for _, tc := range []struct {
		name       string
		statuses   []string
		stopAfter  time.Duration // the flag is set once the wait has run this long; zero means never
		errs       []error
		code       int
		reason     string
		interrupts int
		notes      []string
		calls      []string
	}{
		// Polls run every 10 seconds; checks run at 0s and 30s, and the flag is seen at 30s.
		{"stopped while waiting", statuses(4), 25 * time.Second, nil, exitStopped, stopStopped, 1,
			[]string{stoppedNote}, append(stopped(3), "End")},
		// Running polls at 0s to 90s give checks at 0s, 30s, 60s, and 90s, plus the start-of-collect check.
		{"never set", statuses(10), 0, nil, 0, stopCompleted, 0, []string{}, append(stopped(5), "End")},
		{"transient check error", statuses(10), 0, []error{nil, storageErr}, 0, stopCompleted, 0,
			[]string{stopCheckFailedNote}, append(stopped(5), "End")},
		// Checks at 0s, 30s, and 60s fail; the failure path polls once more and interrupts.
		{"three check errors", statuses(8), 0, []error{nil, storageErr, storageErr, storageErr}, exitStateError, "", 1,
			nil, stopped(4)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clock := testClock()
			s := sessionState(clock.Now())
			s.MinutesLimit = 30
			factory := &fakeFactory{record: &factorystate.InProgress{WorkID: s.WorkID, SessionID: s.SessionID}, generation: 3,
				stoppedErrs: tc.errs}
			out := t.TempDir()
			var interrupts, gets int
			var cleanup []string
			handler := collectHandler(t, out, tc.statuses, &interrupts, &gets, &cleanup)
			r := testRunner(func(req *http.Request) (int, string) {
				if tc.stopAfter > 0 && clock.Now().Sub(s.StartedAt) >= tc.stopAfter {
					factory.stop = &factorystate.StopFlag{Reason: "test"}
				}
				return handler(req)
			}, clock)
			r.factory = factory
			err := r.collect(t.Context(), s, out)
			if !slices.Equal(factory.calls, tc.calls) || interrupts != tc.interrupts {
				t.Fatalf("state calls = %v, want %v; interrupts = %d", factory.calls, tc.calls, interrupts)
			}
			if tc.code == exitStateError {
				if exitCode(err) != exitStateError || !strings.Contains(err.Error(), "storage unavailable") ||
					!strings.Contains(err.Error(), "resources were kept") {
					t.Fatalf("collect = %v (exit %d), want the fail-closed path", err, exitCode(err))
				}
				if _, statErr := os.Stat(filepath.Join(out, "record.partial.json")); !errors.Is(statErr, os.ErrNotExist) ||
					len(cleanup) != 0 || factory.record == nil {
					t.Fatalf("record stat = %v, cleanup = %v, record = %+v; want resources kept", statErr, cleanup, factory.record)
				}
				return
			}
			if (tc.code == 0 && err != nil) || (tc.code != 0 && exitCode(err) != tc.code) {
				t.Fatalf("collect = %v (exit %d), want exit %d", err, exitCode(err), tc.code)
			}
			rec, readErr := readJSON[record.Record](filepath.Join(out, "record.partial.json"))
			if readErr != nil || rec.Validate() != nil || rec.StopReason != tc.reason ||
				rec.Interruptions.Count != tc.interrupts || !slices.Equal(rec.Interruptions.Notes, tc.notes) {
				t.Fatalf("record = %+v, %v", rec, readErr)
			}
			if !slices.Equal(cleanup, wantCleanup) || factory.record != nil {
				t.Fatalf("cleanup = %v, record = %+v", cleanup, factory.record)
			}
		})
	}
}

func TestCollectWithoutStateSkipsStopChecks(t *testing.T) {
	const running = `{"status":"running"}`
	clock := testClock()
	s := sessionState(clock.Now())
	s.MinutesLimit = 30
	out := t.TempDir()
	var interrupts, gets int
	var cleanup []string
	statuses := append(slices.Repeat([]string{running}, 10), `{"status":"idle","usage":{"active_seconds":3}}`)
	r := testRunner(collectHandler(t, out, statuses, &interrupts, &gets, &cleanup), clock)
	if err := r.collect(t.Context(), s, out); err != nil {
		t.Fatal(err)
	}
	rec, err := readJSON[record.Record](filepath.Join(out, "record.partial.json"))
	if err != nil || rec.StopReason != stopCompleted || interrupts != 0 || len(rec.Interruptions.Notes) != 0 {
		t.Fatalf("record = %+v, %v; interrupts = %d", rec, err, interrupts)
	}
	var watch stopWatch
	if stop, err := r.pollStop(t.Context(), &watch); stop || err != nil || watch.checked {
		t.Fatalf("pollStop without state = %v, %v, checked = %v", stop, err, watch.checked)
	}
}

func TestWorkerRechecksStopFlagWhileWaiting(t *testing.T) {
	storageErr := errors.New("storage unavailable")
	for _, tc := range []struct {
		name  string
		errs  []error
		code  int
		calls []string
	}{
		{"stopped while waiting", nil, exitStopped, []string{"Stopped", "Stopped", "Stopped", "End"}},
		{"three check errors", []error{nil, storageErr, storageErr, storageErr}, exitStateError,
			[]string{"Stopped", "Stopped", "Stopped", "Stopped"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clock := testClock()
			s := sessionState(clock.Now())
			s.Candidate, s.MinutesLimit = workerCandidate, 30
			factory := &fakeFactory{record: &factorystate.InProgress{WorkID: s.WorkID}, generation: 1, stoppedErrs: tc.errs}
			out := t.TempDir()
			var routes []string
			var stoppedAt time.Time
			r := workerTestRunner(t, clock, func(w http.ResponseWriter, req *http.Request) {
				suffix := strings.TrimPrefix(req.URL.Path, "/runs/"+s.WorkID)
				routes = append(routes, req.Method+" "+suffix)
				switch {
				case req.Method == http.MethodPost && suffix == "/stop":
					if string(readRequest(t, req)) != `{"reason":"cancelled"}` {
						t.Error("worker stop did not use the cancelled reason")
					}
					stoppedAt = clock.Now()
					fmt.Fprint(w, `{"state":"finished","stop_reason":"cancelled"}`)
				case req.Method == http.MethodGet && suffix == "":
					if tc.errs == nil && clock.Now().Sub(s.StartedAt) >= 25*time.Second {
						factory.stop = &factorystate.StopFlag{Reason: "test"}
					}
					state, reason := "running", ""
					if !stoppedAt.IsZero() {
						state, reason = "finished", "cancelled"
					}
					fmt.Fprintf(w, `{"id":%q,"state":%q,"stop_reason":%q,"started_at":%q,"finished_at":%q}`,
						s.WorkID, state, reason, s.StartedAt.Format(time.RFC3339), clock.Now().Format(time.RFC3339))
				case suffix == "/egress":
					w.Header().Set("x-egress-dropped", "0")
				case req.Method == http.MethodDelete:
					w.WriteHeader(204)
				default:
					w.WriteHeader(404)
					fmt.Fprint(w, `{"error":"not_found"}`)
				}
			})
			r.factory = factory
			err := r.collect(t.Context(), s, out)
			if exitCode(err) != tc.code || !slices.Equal(factory.calls, tc.calls) {
				t.Fatalf("worker collect = %v (exit %d), state calls = %v; want exit %d, calls %v",
					err, exitCode(err), factory.calls, tc.code, tc.calls)
			}
			if tc.code == exitStateError {
				if !strings.Contains(err.Error(), "storage unavailable") || slices.Contains(routes, "POST /stop") ||
					slices.Contains(routes, "DELETE ") || factory.record == nil {
					t.Fatalf("err = %v, routes = %v, record = %+v; want the start-of-collect failure behaviour",
						err, routes, factory.record)
				}
				return
			}
			rec, readErr := readJSON[record.Record](filepath.Join(out, "record.partial.json"))
			if readErr != nil || rec.StopReason != stopStopped || rec.Interruptions.Count != 1 ||
				!slices.Equal(rec.Interruptions.Notes, []string{stoppedNote}) {
				t.Fatalf("record = %+v, %v", rec, readErr)
			}
			if !stoppedAt.Equal(s.StartedAt.Add(30*time.Second)) || routes[len(routes)-1] != "DELETE " || factory.record != nil {
				t.Fatalf("stopped at %s, routes = %v, record = %+v", stoppedAt, routes, factory.record)
			}
		})
	}
}

func TestWorkerWaitNotesTransientStopCheckError(t *testing.T) {
	clock := testClock()
	s := sessionState(clock.Now())
	s.Candidate, s.MinutesLimit = workerCandidate, 30
	factory := &fakeFactory{stoppedErrs: []error{errors.New("storage unavailable")}}
	r := workerTestRunner(t, clock, func(w http.ResponseWriter, req *http.Request) {
		state := "running"
		if clock.Now().Sub(s.StartedAt) >= 40*time.Second {
			state = "lost"
		}
		fmt.Fprintf(w, `{"id":%q,"state":%q}`, s.WorkID, state)
	})
	r.factory = factory
	status, interruptions, err := r.waitWorker(t.Context(), s)
	if err != nil || status.State != "lost" || interruptions.Count != 0 ||
		!slices.Equal(interruptions.Notes, []string{stopCheckFailedNote}) ||
		!slices.Equal(factory.calls, []string{"Stopped", "Stopped"}) {
		t.Fatalf("wait = %+v, %+v, %v; state calls = %v", status, interruptions, err, factory.calls)
	}
}

func TestCleanupEndsRecord(t *testing.T) {
	clock := testClock()
	s := sessionState(clock.Now())
	path := filepath.Join(t.TempDir(), "state.json")
	if err := writeJSON(path, s, delivery.WriteNew); err != nil {
		t.Fatal(err)
	}
	other := &factorystate.InProgress{WorkID: "p0-20261119T000000Z-00000002"}
	for _, tc := range []struct {
		name   string
		record *factorystate.InProgress
		want   *factorystate.InProgress
	}{
		{"own record", &factorystate.InProgress{WorkID: s.WorkID}, nil},
		{"absent", nil, nil},
		{"other unit", other, other},
	} {
		t.Run(tc.name, func(t *testing.T) {
			factory := &fakeFactory{record: tc.record, generation: 1}
			r := testRunner(func(req *http.Request) (int, string) {
				if req.Method == http.MethodGet {
					return 200, `{"status":"idle"}`
				}
				return 200, "{}"
			}, clock)
			r.factory = factory
			if err := r.run(t.Context(), []string{"cleanup", "-state", path}); err != nil {
				t.Fatal(err)
			}
			if factory.record != tc.want || !slices.Equal(factory.calls, []string{"End"}) {
				t.Fatalf("record = %+v, calls = %v", factory.record, factory.calls)
			}
		})
	}
}

func TestStateCommand(t *testing.T) {
	var stdout bytes.Buffer
	factory := &fakeFactory{}
	r := runner{factory: factory, stdout: &stdout}
	if err := r.run(t.Context(), []string{"state", "check"}); err != nil || stdout.String() != "{\"stopped\":false}\n" {
		t.Fatalf("check = %v, %q", err, stdout.String())
	}
	stdout.Reset()
	if err := r.run(t.Context(), []string{"state", "stop", "-reason", "judge broke", "-stage", "collect", "-work-id", "w-1"}); err != nil ||
		stdout.String() != "{\"stopped\":true,\"already_set\":false}\n" {
		t.Fatalf("stop = %v, %q", err, stdout.String())
	}
	stdout.Reset()
	if err := r.run(t.Context(), []string{"state", "stop", "-reason", "again", "-stage", "reflect"}); err != nil ||
		stdout.String() != "{\"stopped\":true,\"already_set\":true}\n" || factory.stop.Reason != "judge broke" {
		t.Fatalf("second stop = %v, %q", err, stdout.String())
	}
	stdout.Reset()
	err := r.run(t.Context(), []string{"state", "check"})
	if exitCode(err) != exitStopped ||
		stdout.String() != "{\"stopped\":true,\"reason\":\"judge broke\",\"set_by\":\"collect\",\"work_id\":\"w-1\",\"set_at\":\"0001-01-01T00:00:00Z\"}\n" {
		t.Fatalf("stopped check = %v (exit %d), %q", err, exitCode(err), stdout.String())
	}
	for _, args := range [][]string{
		{"state"}, {"state", "unknown"}, {"state", "stop", "-stage", "collect"}, {"state", "check", "extra"},
	} {
		if err := r.run(t.Context(), args); exitCode(err) != exitStateError {
			t.Errorf("%v = %v, want exit %d", args, err, exitStateError)
		}
	}
	factory.stoppedErr = errors.New("storage unavailable")
	if err := r.run(t.Context(), []string{"state", "check"}); exitCode(err) != exitStateError {
		t.Fatalf("failed check = %v, want exit %d", err, exitStateError)
	}
	if err := (runner{}).run(t.Context(), []string{"state", "check"}); exitCode(err) != exitStateError ||
		!strings.Contains(err.Error(), "not configured") {
		t.Fatalf("unconfigured check = %v", err)
	}
	if slices.Contains(factory.calls, "End") || slices.Contains(factory.calls, "Begin") {
		t.Fatal("state commands touched the in-progress record")
	}
}

func TestWorkerStateHooks(t *testing.T) {
	clock := testClock()
	s := sessionState(clock.Now())
	s.Candidate, s.MinutesLimit = workerCandidate, 30
	factory := &fakeFactory{stop: &factorystate.StopFlag{Reason: "test"},
		record: &factorystate.InProgress{WorkID: s.WorkID}, generation: 1}
	out := t.TempDir()
	var routes []string
	stopped := false
	r := workerTestRunner(t, clock, func(w http.ResponseWriter, req *http.Request) {
		suffix := strings.TrimPrefix(req.URL.Path, "/runs/"+s.WorkID)
		routes = append(routes, req.Method+" "+suffix)
		switch {
		case req.Method == http.MethodPost && suffix == "/stop":
			if string(readRequest(t, req)) != `{"reason":"cancelled"}` {
				t.Error("worker stop did not use the cancelled reason")
			}
			stopped = true
			fmt.Fprint(w, `{"state":"finished","stop_reason":"cancelled"}`)
		case req.Method == http.MethodGet && suffix == "":
			state, reason := "running", ""
			if stopped {
				state, reason = "finished", "cancelled"
			}
			fmt.Fprintf(w, `{"id":%q,"state":%q,"stop_reason":%q,"started_at":%q,"finished_at":%q}`,
				s.WorkID, state, reason, s.StartedAt.Format(time.RFC3339), clock.Now().Format(time.RFC3339))
		case req.Method == http.MethodPut && suffix == "/token":
		case suffix == "/egress":
			w.Header().Set("x-egress-dropped", "0")
		case req.Method == http.MethodDelete:
			w.WriteHeader(204)
		default:
			w.WriteHeader(404)
			fmt.Fprint(w, `{"error":"not_found"}`)
		}
	})
	r.factory = factory
	err := r.collect(t.Context(), s, out)
	if exitCode(err) != exitStopped {
		t.Fatalf("worker collect = %v, want exit %d", err, exitStopped)
	}
	rec, readErr := readJSON[record.Record](filepath.Join(out, "record.partial.json"))
	if readErr != nil || rec.StopReason != stopStopped || !slices.Contains(rec.Interruptions.Notes, stoppedNote) {
		t.Fatalf("record = %+v, %v", rec, readErr)
	}
	if !slices.Contains(routes, "POST /stop") || routes[len(routes)-1] != "DELETE " || factory.record != nil {
		t.Fatalf("routes = %v, record = %+v", routes, factory.record)
	}
}

func TestWorkerStartRecordsSession(t *testing.T) {
	t.Chdir("../..")
	t.Setenv("FACTORY_COMMIT", factoryCommit)
	cfg, dir, manifest := preparedFiles(t)
	if err := os.Remove(filepath.Join(dir, manifest.Files[5].Name)); err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(t.TempDir(), "state.json")
	clock := testClock()
	factory := &fakeFactory{}
	r := workerTestRunner(t, clock, func(w http.ResponseWriter, req *http.Request) {
		if factory.record == nil {
			t.Error("worker request before the in-progress record")
		}
		switch {
		case strings.HasSuffix(req.URL.Path, "/start"):
			w.WriteHeader(202)
			fmt.Fprintf(w, `{"state":"running","started_at":%q,"worker_version":{"id":"v"},"factory_commit":"c"}`,
				clock.Now().Format(time.RFC3339))
		case strings.Contains(req.URL.Path, "/files/"):
			data := readRequest(t, req)
			fmt.Fprintf(w, `{"name":"x","bytes":%d,"sha256":"%x"}`, len(data), sha256.Sum256(data))
		}
	})
	r.factory = factory
	if err := r.start(t.Context(), cfg, "fixer", workerCandidate, dir, statePath, 0, 0); err != nil {
		t.Fatal(err)
	}
	s, err := readJSON[state](statePath)
	if err != nil || factory.record == nil || factory.record.SessionID != s.WorkID || factory.record.Candidate != workerCandidate ||
		!slices.Equal(factory.calls, []string{"Stopped", "Begin", "Current", "Update"}) {
		t.Fatalf("record = %+v, calls = %v, state error = %v", factory.record, factory.calls, err)
	}
}
