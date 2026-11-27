package main

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestPush(t *testing.T) {
	f := setup(t, nil)
	role := edit(stateFile)
	stageInputs(t, f, role, "", fixtureJudgedTree(t, f, role, ""), nil)
	runExpect(t, verifyArgs(f, false), 0, "")
	runExpect(t, commitArgs(f, false), 0, "")
	reflected := loadJSON[commitResult](t, f.result)
	moved, err := createCommit(f.product, reflected.Tree, f.base, "Some other commit\n")
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name, remoteRef, reason      string
		change                       func(*commitResult, []string)
		defaultBranch, optIn, noHook bool
		unbornHead                   bool
	}{
		{name: "absent ref"},
		{name: "ref at base", remoteRef: f.base},
		{name: "local path without test hook", noHook: true, reason: "remote is not allowed"},
		{name: "default branch rejected", remoteRef: f.base, defaultBranch: true, reason: "target ref is the default branch"},
		{name: "default branch opted in", remoteRef: f.base, defaultBranch: true, optIn: true},
		{name: "no advertised default branch", unbornHead: true, reason: "cannot determine remote default branch"},
		{name: "moved ref", remoteRef: moved, reason: "target ref moved"},
		{name: "SSH remote", reason: "remote is not allowed", change: setRemote("ssh://github.com/toshi0607/google-cloud-emulator.git")},
		{name: "other host", reason: "remote is not allowed", change: setRemote("https://evil.example/x.git")},
		{name: "other repository", reason: "remote is not allowed", change: setRemote("https://github.com/other/repo.git")},
		{name: "userinfo", reason: "remote is not allowed", change: setRemote("https://user@github.com/toshi0607/google-cloud-emulator.git")},
		{name: "relative path", reason: "remote is not allowed", change: setRemote("remote.git")},
		{name: "result target mismatch", reason: "commit result target ref mismatch", change: func(result *commitResult, _ []string) {
			result.TargetRef = "refs/heads/other"
		}},
		{name: "disallowed target", reason: "target ref is not allowed", change: func(result *commitResult, args []string) {
			result.TargetRef = "refs/heads/other"
			setFlag(args, "-target-ref", result.TargetRef)
		}},
		{name: "tree mismatch", reason: "commit result tree mismatch", change: func(result *commitResult, _ []string) {
			result.Tree = factoryID
		}},
		{name: "parent mismatch", reason: "commit result parent mismatch", change: func(result *commitResult, _ []string) {
			result.Parent = moved
		}},
		{name: "missing commit", reason: "does not name a product commit", change: func(result *commitResult, _ []string) {
			result.Commit = factoryID
		}},
		{name: "tree object", reason: "does not name a product commit", change: func(result *commitResult, _ []string) {
			result.Commit = result.Tree
		}},
		{name: "missing trailer", reason: "missing a valid Factory-Work-Id trailer", change: func(result *commitResult, _ []string) {
			result.Commit = moved
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			allowLocalRemoteForTest = !tc.noHook
			t.Cleanup(func() { allowLocalRemoteForTest = false })
			dir := t.TempDir()
			remote := filepath.Join(dir, "remote.git")
			testGit(t, dir, "init", "--bare", "--template=", "--initial-branch=main", remote)
			if !tc.unbornHead {
				testGit(t, f.product, "push", "--no-verify", remote, f.base+":refs/heads/main")
			}
			if tc.remoteRef != "" {
				testGit(t, f.product, "push", "--no-verify", remote, tc.remoteRef+":"+testTargetRef)
			}
			if tc.defaultBranch {
				testGit(t, remote, "symbolic-ref", "HEAD", testTargetRef)
			}
			// ls-remote patterns also match ref suffixes. Leave a different ref with that suffix.
			decoy := "refs/heads/decoy/" + testTargetRef
			testGit(t, f.product, "push", "--no-verify", remote, moved+":"+decoy)
			before := testGit(t, remote, "for-each-ref")

			result := reflected
			resultPath, out := filepath.Join(dir, "commit.json"), filepath.Join(dir, "push.json")
			policyPath := f.policy
			if tc.optIn {
				data, err := os.ReadFile(f.policy)
				if err != nil {
					t.Fatal(err)
				}
				policyPath = filepath.Join(dir, "policy.yaml")
				put(t, policyPath, string(data)+"  default_branch_allowed: true\n")
			}
			args := []string{"push", "-policy", policyPath, "-product", f.product, "-result", resultPath,
				"-remote", remote, "-target-ref", testTargetRef, "-out", out}
			if tc.change != nil {
				tc.change(&result, args)
			}
			if err := writeJSON(resultPath, result); err != nil {
				t.Fatal(err)
			}

			// A local transport must not inherit any credential or other Git configuration.
			t.Setenv("GIT_CONFIG_COUNT", "1")
			t.Setenv("GIT_CONFIG_KEY_0", "core.repositoryformatversion")
			t.Setenv("GIT_CONFIG_VALUE_0", "999")
			if tc.reason != "" {
				code := 1
				if tc.unbornHead {
					code = 2
				}
				runExpect(t, args, code, tc.reason)
				if _, err := os.Stat(out); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("push result after rejection: %v", err)
				}
				if after := testGit(t, remote, "for-each-ref"); after != before {
					t.Fatalf("remote refs changed after rejection\nbefore: %s\nafter: %s", before, after)
				}
				return
			}
			runExpect(t, args, 0, "")
			want := pushResult{Pushed: true, Commit: reflected.Commit, TargetRef: testTargetRef, Previous: tc.remoteRef}
			if got := loadJSON[pushResult](t, out); got != want {
				t.Fatalf("push result = %+v, want %+v", got, want)
			}
			if got := testGit(t, remote, "rev-parse", testTargetRef); got != reflected.Commit {
				t.Fatalf("remote target = %s, want %s", got, reflected.Commit)
			}
			if got := testGit(t, remote, "rev-parse", decoy); got != moved {
				t.Fatalf("remote decoy = %s, want %s", got, moved)
			}
		})
	}
}

func TestGitHubAuthEnv(t *testing.T) {
	valid := []string{"GIT_CONFIG_COUNT=1", "GIT_CONFIG_KEY_0=" + githubAuthKey, "GIT_CONFIG_VALUE_0=AUTHORIZATION: basic dummy"}
	for _, tc := range []struct {
		name string
		env  []string
		ok   bool
	}{
		{"no authentication", []string{"PATH=/usr/bin"}, true},
		{"one extraheader", append([]string{"PATH=/usr/bin"}, valid...), true},
		{"different key", []string{valid[0], "GIT_CONFIG_KEY_0=core.hooksPath", valid[2]}, false},
		{"missing value", valid[:2], false},
		{"duplicate key", []string{valid[0], valid[1], valid[1]}, false},
		{"only value", valid[2:], false},
		{"additional key", append(slices.Clone(valid), "GIT_CONFIG_KEY_1=include.path"), false},
		{"multiple entries", []string{"GIT_CONFIG_COUNT=2", valid[1], valid[2]}, false},
		{"config parameters", []string{"GIT_CONFIG_PARAMETERS=unused"}, false},
		{"global config", append(slices.Clone(valid), "GIT_CONFIG_GLOBAL=/tmp/other"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, problem := githubAuthEnv(tc.env)
			if !tc.ok {
				if problem == nil || problem.code != 2 || problem.reason != "invalid Git authentication configuration" {
					t.Fatalf("expected configuration refusal, got %v", problem)
				}
				return
			}
			if problem != nil || !slices.Equal(got, tc.env[1:]) {
				t.Fatalf("auth environment = %q, problem = %v", got, problem)
			}
		})
	}
}

func setRemote(remote string) func(*commitResult, []string) {
	return func(_ *commitResult, args []string) { setFlag(args, "-remote", remote) }
}

func TestSanitizeGitError(t *testing.T) {
	message := "fatal: AUTHORIZATION: basic abcd\n" +
		"fatal: Authorization: bearer xyz\n" +
		"url: https://x-access-token:small-secret@github.com/example.git\n" +
		"trace: " + strings.Repeat("ab+/", 11) + "==\n" +
		"short: " + strings.Repeat("0", 40)
	want := "fatal: [redacted]\n" +
		"fatal: [redacted]\n" +
		"url: https://[redacted]@github.com/example.git\n" +
		"trace: [redacted]\n" +
		"short: " + strings.Repeat("0", 40)
	if got := sanitizeGitError(message); got != want {
		t.Fatalf("sanitized message = %q, want %q", got, want)
	}
}
