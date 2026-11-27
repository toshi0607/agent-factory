package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPush(t *testing.T) {
	f := setup(t, nil)
	stageInputs(t, f, edit(stateFile), "", "", nil)
	runExpect(t, verifyArgs(f, false), 0, "")
	runExpect(t, commitArgs(f, false), 0, "")
	reflected := loadJSON[commitResult](t, f.result)
	moved, err := createCommit(f.product, reflected.Tree, f.base, "Some other commit\n")
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name, remoteRef, reason string
		change                  func(*commitResult, []string)
	}{
		{name: "absent ref"},
		{name: "ref at base", remoteRef: f.base},
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
			dir := t.TempDir()
			remote := filepath.Join(dir, "remote.git")
			testGit(t, dir, "init", "--bare", "--template=", remote)
			if tc.remoteRef != "" {
				testGit(t, f.product, "push", "--no-verify", remote, tc.remoteRef+":"+testTargetRef)
			}
			// ls-remote patterns also match ref suffixes. Leave a different ref with that suffix.
			decoy := "refs/heads/decoy/" + testTargetRef
			testGit(t, f.product, "push", "--no-verify", remote, moved+":"+decoy)
			before := testGit(t, remote, "for-each-ref")

			result := reflected
			resultPath, out := filepath.Join(dir, "commit.json"), filepath.Join(dir, "push.json")
			args := []string{"push", "-policy", f.policy, "-product", f.product, "-result", resultPath,
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
				runExpect(t, args, 1, tc.reason)
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
