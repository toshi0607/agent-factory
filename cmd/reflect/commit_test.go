package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/toshi0607/agent-factory/internal/patchcheck"
)

func TestCommit(t *testing.T) {
	for _, tc := range []struct {
		name, gen, reason string
		change            func(*testing.T, fixture, *decision, []string)
	}{
		{name: "role only"},
		{name: "with generated patch", gen: edit(generatedFile)},
		{name: "accepted flipped", reason: "decision is not accepted", change: func(_ *testing.T, _ fixture, d *decision, _ []string) {
			d.Accepted = false
		}},
		{name: "decision hash changed", reason: "patch hash mismatch", change: func(_ *testing.T, _ fixture, d *decision, _ []string) {
			d.PatchSHA256 = digest([]byte("different"))
		}},
		{name: "generated hash changed", gen: edit(generatedFile), reason: "patch hash mismatch", change: func(_ *testing.T, _ fixture, d *decision, _ []string) {
			d.GenPatchSHA256 = new(digest([]byte("different")))
		}},
		{name: "policy changed", reason: "policy hash mismatch", change: func(t *testing.T, f fixture, _ *decision, _ []string) {
			data, err := os.ReadFile(f.policy)
			if err != nil {
				t.Fatal(err)
			}
			put(t, f.policy, string(data)+"# changed\n")
		}},
		{name: "target ref disallowed", reason: "target ref is not allowed", change: func(_ *testing.T, _ fixture, _ *decision, args []string) {
			setFlag(args, "-target-ref", "refs/heads/no")
		}},
		{name: "patch file swapped", reason: "patch hash mismatch", change: func(t *testing.T, f fixture, _ *decision, _ []string) {
			put(t, f.patch, add("services/secretmanager/replacement.go"))
		}},
		{name: "tree changed", reason: "decision tree mismatch", change: func(_ *testing.T, _ fixture, d *decision, _ []string) {
			d.TreeSHA = factoryID
		}},
		{name: "judged tree changed", gen: edit(generatedFile), reason: "judged tree mismatch", change: func(_ *testing.T, _ fixture, d *decision, _ []string) {
			d.JudgedTree = new(factoryID)
		}},
		{name: "changed patch and matching fake decision hash", reason: "protected path", change: func(t *testing.T, f fixture, d *decision, _ []string) {
			patch := add(".github/workflows/policy.yml")
			put(t, f.patch, patch)
			d.PatchSHA256 = digest([]byte(patch))
		}},
		{name: "work id injection", reason: "invalid factory commit or work id", change: func(_ *testing.T, _ fixture, d *decision, _ []string) {
			d.WorkID += "\nFactory-Role: other"
		}},
		{name: "dependency grant must be present at commit", gen: edit("go.sum"), reason: "dependency file requires"},
		{name: "dependency grant present at commit", gen: edit("go.sum"), change: func(_ *testing.T, _ fixture, _ *decision, args []string) {
			args[len(args)-1] = "-allow-dependency-changes"
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := setup(t, nil)
			testGit(t, f.product, "branch", "other")
			role := edit(stateFile)
			var judgedTree string
			if tc.gen != "" {
				judgedTree = fixtureJudgedTree(t, f, role, tc.gen)
			}
			stageInputs(t, f, role, tc.gen, judgedTree, nil)
			verify := verifyArgs(f, tc.gen != "")
			if tc.gen == edit("go.sum") {
				verify = append(verify, "-allow-dependency-changes")
			}
			runExpect(t, verify, 0, "")
			d := loadJSON[decision](t, f.decision)
			refs := testGit(t, f.product, "for-each-ref", "refs/heads")
			args := append(commitArgs(f, tc.gen != ""), "--")
			if tc.change != nil {
				tc.change(t, f, &d, args)
				if err := writeJSON(f.decision, d); err != nil {
					t.Fatal(err)
				}
			}
			if tc.reason != "" {
				runExpect(t, args, 1, tc.reason)
				if _, err := os.Stat(f.result); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("result after rejection: %v", err)
				}
				if head := testGit(t, f.product, "rev-parse", "HEAD"); head != f.base {
					t.Fatalf("rejection changed HEAD to %s", head)
				}
			} else {
				runExpect(t, args, 0, "")
				checkCommit(t, f, d)
			}
			if got := testGit(t, f.product, "for-each-ref", "refs/heads"); got != refs {
				t.Fatalf("changed branch refs\nwant: %s\ngot: %s", refs, got)
			}
		})
	}
}

func checkCommit(t *testing.T, f fixture, d decision) {
	t.Helper()
	result := loadJSON[commitResult](t, f.result)
	if !objectID.MatchString(result.Commit) || result.Parent != f.base || result.Tree != d.TreeSHA || result.TargetRef != testTargetRef {
		t.Fatalf("unexpected result: %+v", result)
	}
	if head := testGit(t, f.product, "rev-parse", "HEAD"); head != result.Commit {
		t.Fatalf("HEAD = %q, want %q", head, result.Commit)
	}
	if tree := testGit(t, f.product, "rev-parse", "HEAD^{tree}"); tree != d.TreeSHA {
		t.Fatalf("tree = %q, want %q", tree, d.TreeSHA)
	}
	if parent := testGit(t, f.product, "rev-list", "--parents", "-1", "HEAD"); parent != result.Commit+" "+f.base {
		t.Fatalf("unexpected parents: %s", parent)
	}
	if got := testGit(t, f.product, "status", "--porcelain"); got != "" {
		t.Fatalf("dirty product after commit: %s", got)
	}
	raw, err := patchcheck.Git(f.product, nil, "cat-file", "commit", "HEAD")
	if err != nil {
		t.Fatal(err)
	}
	headers, message, _ := strings.Cut(string(raw), "\n\n")
	for _, field := range []string{"author", "committer"} {
		if !strings.Contains(headers, "\n"+field+" agent-factory <agent-factory@users.noreply.github.com> ") {
			t.Fatalf("missing fixed %s: %s", field, headers)
		}
	}
	if strings.Contains(headers, "\ngpgsig ") {
		t.Fatal("unexpected commit signature")
	}
	genTrailer := ""
	if d.GenPatchSHA256 != nil {
		genTrailer = fmt.Sprintf("Factory-Gen-Patch-Sha256: %s\n", *d.GenPatchSHA256)
	}
	want := fmt.Sprintf("factory(fixer): sm-create-get\n\n"+
		"Factory-Work-Id: %s\nFactory-Role: fixer\nFactory-Task: sm-create-get\n"+
		"Factory-Base-Commit: %s\nFactory-Patch-Sha256: %s\n%sFactory-Policy-Sha256: %s\nFactory-Commit: %s\n",
		testWorkID, f.base, d.PatchSHA256, genTrailer, d.PolicySHA256, factoryID)
	if message != want {
		t.Fatalf("commit message\nwant: %q\ngot: %q", want, message)
	}
}

func TestUntrustedGitConfiguration(t *testing.T) {
	f := setup(t, nil)
	role, gen := edit(stateFile), edit(generatedFile)
	stageInputs(t, f, role, gen, fixtureJudgedTree(t, f, role, gen), nil)
	config := filepath.Join(f.product, ".git/config")
	original, err := os.ReadFile(config)
	if err != nil {
		t.Fatal(err)
	}
	put(t, filepath.Join(f.product, ".git/info/attributes"), "*.go filter=untrusted\n")
	put(t, filepath.Join(f.product, ".git/invalid-config"), "this is not a git configuration file\n")
	put(t, config, string(original)+`
[core]
	hooksPath = .git/untrusted-hooks
	fsmonitor = /nonexistent/untrusted-fsmonitor
[filter "untrusted"]
	required = true
	process = /nonexistent/untrusted-filter
[diff "untrusted"]
	textconv = /nonexistent/untrusted-textconv
[include]
	path = invalid-config
`)
	t.Setenv("GIT_CONFIG_COUNT", "1")
	t.Setenv("GIT_CONFIG_KEY_0", "core.hooksPath")
	t.Setenv("GIT_CONFIG_VALUE_0", ".git/untrusted-hooks")
	t.Setenv("GIT_DIR", filepath.Join(t.TempDir(), "other"))
	runExpect(t, verifyArgs(f, true), 0, "")
	runExpect(t, commitArgs(f, true), 0, "")
	got, err := os.ReadFile(config)
	if err != nil || !strings.Contains(string(got), "path = invalid-config") {
		t.Fatalf("product config was altered: %v", err)
	}
	put(t, config, string(original))
	if err := os.Remove(filepath.Join(f.product, ".git/info/attributes")); err != nil {
		t.Fatal(err)
	}
	checkCommit(t, f, loadJSON[decision](t, f.decision))
}

func TestShallowProduct(t *testing.T) {
	f := setup(t, nil)
	testGit(t, f.product, "-c", "user.name=fixture", "-c", "user.email=fixture@invalid", "commit", "--allow-empty", "-m", "shallow tip")
	f.base = testGit(t, f.product, "rev-parse", "HEAD")
	put(t, filepath.Join(f.product, ".git/shallow"), f.base+"\n")
	role, gen := edit(stateFile), edit(generatedFile)
	stageInputs(t, f, role, gen, fixtureJudgedTree(t, f, role, gen), nil)
	runExpect(t, verifyArgs(f, true), 0, "")
	runExpect(t, commitArgs(f, true), 0, "")
	checkCommit(t, f, loadJSON[decision](t, f.decision))
}
