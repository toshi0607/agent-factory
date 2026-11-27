package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/toshi0607/agent-factory/internal/patchcheck"
	"github.com/toshi0607/agent-factory/poc/record"
)

const (
	roleName       = "fixer"
	taskName       = "sm-create-get"
	testWorkID     = "p0-20261127T012345Z-1234abcd"
	testTargetRef  = "refs/heads/factory-f0"
	stateFile      = "services/secretmanager/state.go"
	generatedFile  = "services/secretmanager/state.gen.go"
	otherStateFile = "services/pubsub/state.go"
	factoryID      = "1111111111111111111111111111111111111111"
)

type fixture struct {
	product, base, policy, patch, gen, judge, decision, result string
}

func setup(t *testing.T, prepare func(*testing.T, string)) fixture {
	t.Helper()
	root := t.TempDir()
	f := fixture{
		product: filepath.Join(root, "product"), policy: filepath.Join(root, "policy.yaml"),
		patch: filepath.Join(root, "patch.diff"), gen: filepath.Join(root, "gen.diff"),
		judge: filepath.Join(root, "judge.json"), decision: filepath.Join(root, "decision.json"),
		result: filepath.Join(root, "result.json"),
	}
	if err := os.Mkdir(f.product, 0o755); err != nil {
		t.Fatal(err)
	}
	testGit(t, f.product, "init", "--template=", "--initial-branch=factory-f0")
	for name, content := range map[string]string{
		stateFile: "old\n", generatedFile: "old\n", otherStateFile: "old\n",
		"go.mod": "module sample\n", "go.sum": "old\n",
	} {
		put(t, filepath.Join(f.product, name), content)
	}
	if prepare != nil {
		prepare(t, f.product)
	}
	testGit(t, f.product, "add", "--", ".")
	testGit(t, f.product, "-c", "user.name=fixture", "-c", "user.email=fixture@invalid", "commit", "-m", "base")
	f.base = testGit(t, f.product, "rev-parse", "HEAD")
	policy, err := os.ReadFile("../../policy/google-cloud-emulator.yaml")
	if err != nil {
		t.Fatal(err)
	}
	put(t, f.policy, string(policy))
	return f
}

func put(t *testing.T, name, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(name), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func testGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	out, err := patchcheck.Git(dir, nil, args...)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSuffix(string(out), "\n")
}

func loadJSON[T any](t *testing.T, name string) T {
	t.Helper()
	data, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	var artifact T
	if err := json.Unmarshal(data, &artifact); err != nil {
		t.Fatal(err)
	}
	return artifact
}

func add(name string) string {
	return fmt.Sprintf("diff --git a/%[1]s b/%[1]s\nnew file mode 100644\n--- /dev/null\n+++ b/%[1]s\n@@ -0,0 +1 @@\n+new\n", name)
}

func edit(name string) string {
	return fmt.Sprintf("diff --git a/%[1]s b/%[1]s\n--- a/%[1]s\n+++ b/%[1]s\n@@ -1 +1 @@\n-old\n+new\n", name)
}

func deleteFile(name string) string {
	return fmt.Sprintf("diff --git a/%[1]s b/%[1]s\ndeleted file mode 100644\n--- a/%[1]s\n+++ /dev/null\n@@ -1 +0,0 @@\n-old\n", name)
}

func move(operation, old, new string) string {
	return fmt.Sprintf("diff --git a/%s b/%s\nsimilarity index 100%%\n%s from %s\n%s to %s\n", old, new, operation, old, operation, new)
}

func stageInputs(t *testing.T, f fixture, patch, gen string, amend func(*record.CheckResult) string) {
	t.Helper()
	put(t, f.patch, patch)
	judge := record.CheckResult{
		Task: taskName, PatchSHA256: digest([]byte(patch)),
		PathsOK: true, ApplyOK: true, GenOK: true, BuildOK: true, CheckPassed: true,
		GenChangedPaths: []string{}, Failures: []record.Failure{},
	}
	if gen != "" {
		put(t, f.gen, gen)
		judge.GenPatchSHA256 = digest([]byte(gen))
	}
	var extra string
	if amend != nil {
		extra = amend(&judge)
	}
	if extra != "" {
		put(t, f.judge, extra)
	} else if err := writeJSON(f.judge, judge); err != nil {
		t.Fatal(err)
	}
}

func verifyArgs(f fixture, hasGen bool) []string {
	args := []string{"verify", "-policy", f.policy, "-role", roleName, "-task", taskName, "-product", f.product,
		"-base", f.base, "-patch", f.patch, "-judge", f.judge, "-work-id", testWorkID, "-out", f.decision}
	if hasGen {
		args = append(args, "-gen-patch", f.gen)
	}
	return args
}

func commitArgs(f fixture, hasGen bool) []string {
	args := []string{"commit", "-decision", f.decision, "-policy", f.policy, "-product", f.product,
		"-patch", f.patch, "-target-ref", testTargetRef, "-factory-commit", factoryID, "-out", f.result}
	if hasGen {
		args = append(args, "-gen-patch", f.gen)
	}
	return args
}

func setFlag(args []string, name, value string) {
	args[slices.Index(args, name)+1] = value
}

func runExpect(t *testing.T, args []string, code int, reason string) {
	t.Helper()
	var stderr bytes.Buffer
	if got := run(args, &stderr); got != code || !strings.Contains(stderr.String(), reason) {
		t.Fatalf("run = (%d, %q), want (%d, containing %q)", got, stderr.String(), code, reason)
	}
}

func TestVerify(t *testing.T) {
	for _, tc := range []struct {
		name, patch, gen, reason string
		code                     int
		allow                    bool
		prepare                  func(*testing.T, string)
		amend                    func(*record.CheckResult) string
		change                   func(*testing.T, fixture, []string)
	}{
		{name: "edit"},
		{name: "new file", patch: add("services/secretmanager/new.go")},
		{name: "delete", patch: deleteFile(stateFile)},
		{name: "generated", gen: edit(generatedFile)},
		{name: "benign attributes", prepare: func(t *testing.T, dir string) {
			put(t, filepath.Join(dir, ".gitattributes"), `# no filter= here in a comment
"path with filter=" -text
`)
		}},
		{name: "root generated", gen: add("root.gen.go")},
		{name: "outside role", patch: add("outside.go"), code: 1, reason: "outside role"},
		{name: "outside task", patch: edit(otherStateFile), code: 1, reason: "outside task"},
		{name: "rename out", patch: move("rename", stateFile, otherStateFile), code: 1, reason: "outside task"},
		{name: "rename in", patch: move("rename", otherStateFile, stateFile), code: 1, reason: "rename"},
		{name: "copy", patch: move("copy", stateFile, "services/secretmanager/copy.go"), code: 1, reason: "copy"},
		{name: "delete outside", patch: deleteFile(otherStateFile), code: 1, reason: "outside task"},
		{name: "symlink", patch: strings.Replace(add(stateFile), "100644", "120000", 1), code: 1, reason: "symlink"},
		{name: "symlink directory", patch: add(stateFile), code: 1, reason: "symlink", prepare: symlinkService},
		{name: "gitlink", patch: strings.Replace(add(stateFile), "100644", "160000", 1), code: 1, reason: "submodule"},
		{name: "mode", patch: fmt.Sprintf("diff --git a/%[1]s b/%[1]s\nold mode 100644\nnew mode 100755\n", stateFile), code: 1, reason: "unsupported patch operation: mode"},
		{name: "binary", code: 1, reason: "binary patch", change: replaceWithBinaryPatch},
		{name: "workflow", patch: add(".github/workflows/x.yml"), code: 1, reason: "protected"},
		{name: "root instructions", patch: add("CLAUDE.md"), code: 1, reason: "protected"},
		{name: "nested instructions", patch: add("services/x/CLAUDE.md"), code: 1, reason: "protected"},
		{name: "attributes", patch: add(".gitattributes"), code: 1, reason: "protected"},
		{name: "generated in role patch", patch: edit(generatedFile), code: 1, reason: "generated path in role patch"},
		{name: "dependency in role patch even with opt-in", patch: add("go.mod"), allow: true, code: 1, reason: "dependency file in role patch"},
		{name: "non-generated", gen: edit(otherStateFile), code: 1, reason: "outside generated"},
		{name: "dependency without opt-in", gen: edit("go.sum"), code: 1, reason: "dependency file requires"},
		{name: "dependency with opt-in", gen: edit("go.sum"), allow: true},
		{name: "overlap", gen: edit(stateFile), code: 1, reason: "both patches"},
		{name: "judge hash", code: 1, reason: "judge patch hash mismatch", change: func(t *testing.T, f fixture, _ []string) {
			put(t, f.patch, strings.Replace(edit(stateFile), "+new", "+New", 1))
		}},
		{name: "judge failed", code: 1, reason: "failed check", amend: func(r *record.CheckResult) string {
			r.CheckPassed = false
			return ""
		}},
		{name: "judge failure entry", code: 1, reason: "reports failures", amend: func(r *record.CheckResult) string {
			r.Failures = []record.Failure{{Name: "failed", Message: "sensitive content"}}
			return ""
		}},
		{name: "judge unknown field", code: 1, reason: "invalid judge result JSON", amend: func(r *record.CheckResult) string {
			data, err := json.Marshal(r)
			if err != nil {
				panic(err)
			}
			return strings.TrimSuffix(string(data), "}") + ",\"extra\":true}"
		}},
		{name: "judge oversized", code: 1, reason: "judge result exceeds size limit", amend: func(*record.CheckResult) string {
			return strings.Repeat(" ", maxJudgeSize+1)
		}},
		{name: "missing generated patch", code: 1, reason: "requires a generated patch", amend: func(r *record.CheckResult) string {
			r.GenChangedPaths = []string{generatedFile}
			return ""
		}},
		{name: "missing generated patch hash", gen: edit(generatedFile), code: 1, reason: "lacks a generated patch hash", amend: func(r *record.CheckResult) string {
			r.GenPatchSHA256 = ""
			return ""
		}},
		{name: "generated patch hash mismatch", gen: edit(generatedFile), code: 1, reason: "generated patch hash mismatch", amend: func(r *record.CheckResult) string {
			r.GenPatchSHA256 = digest([]byte("different"))
			return ""
		}},
		{name: "wrong HEAD", code: 1, reason: "does not equal product HEAD", change: func(_ *testing.T, _ fixture, args []string) {
			setFlag(args, "-base", factoryID)
		}},
		{name: "dirty", code: 1, reason: "dirty product worktree", change: func(t *testing.T, f fixture, _ []string) {
			put(t, filepath.Join(f.product, stateFile), "dirty\n")
		}},
		{name: "dirty index", code: 1, reason: "dirty product index", change: func(t *testing.T, f fixture, _ []string) {
			put(t, filepath.Join(f.product, stateFile), "staged\n")
			testGit(t, f.product, "add", "--", stateFile)
		}},
		{name: "hidden dirty file", code: 1, reason: "dirty product worktree", change: func(t *testing.T, f fixture, _ []string) {
			testGit(t, f.product, "update-index", "--assume-unchanged", stateFile)
			put(t, filepath.Join(f.product, stateFile), "dirty\n")
		}},
		{name: "filter attribute", code: 1, reason: "base .gitattributes contains filter=", prepare: func(t *testing.T, dir string) {
			put(t, filepath.Join(dir, "services/secretmanager/.gitattributes"), "*.go filter=inert\n")
		}},
		{name: "raw traversal", patch: "--- /dev/null\n+++ ../" + stateFile + "\n@@ -0,0 +1 @@\n+new\n", code: 1, reason: "unsafe patch path"},
		{name: "raw absolute", patch: "--- /dev/null\n+++ /" + stateFile + "\n@@ -0,0 +1 @@\n+new\n", code: 1, reason: "unsafe patch path"},
		{name: "role without write", code: 2, reason: "has no write", change: func(_ *testing.T, _ fixture, args []string) {
			setFlag(args, "-role", "probe")
		}},
		{name: "patch is a symlink", code: 1, reason: "regular file", change: func(t *testing.T, f fixture, args []string) {
			link := f.patch + ".link"
			if err := os.Symlink(f.patch, link); err != nil {
				t.Fatal(err)
			}
			setFlag(args, "-patch", link)
		}},
		{name: "oversized patch", code: 1, reason: "role patch exceeds size limit", change: func(t *testing.T, f fixture, _ []string) {
			put(t, f.patch, strings.Repeat(" ", maxPatchSize+1))
		}},
		{name: "patch does not apply", patch: strings.Replace(edit(stateFile), "-old", "-different", 1), code: 1, reason: "does not apply cleanly"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := setup(t, tc.prepare)
			patch := tc.patch
			if patch == "" {
				patch = edit(stateFile)
			}
			stageInputs(t, f, patch, tc.gen, tc.amend)
			args := verifyArgs(f, tc.gen != "")
			if tc.allow {
				args = append(args, "-allow-dependency-changes")
			}
			if tc.change != nil {
				tc.change(t, f, args)
			}
			runExpect(t, args, tc.code, tc.reason)
			d := loadJSON[decision](t, f.decision)
			if d.Accepted != (tc.code == 0) || !strings.Contains(d.Reason, tc.reason) || strings.ContainsAny(d.Reason, "\r\n") {
				t.Fatalf("unexpected decision: %+v", d)
			}
			info, err := os.Stat(f.decision)
			if err != nil || info.Mode().Perm() != 0o600 {
				t.Fatalf("decision mode: %v, %v", info, err)
			}
			if d.Accepted && (!objectID.MatchString(d.TreeSHA) || len(d.Paths) != 1 || len(d.GenPaths) != lenGen(tc.gen) ||
				d.WorkID != testWorkID || d.BaseCommit != f.base || d.PatchSHA256 != digest([]byte(patch))) {
				t.Fatalf("incomplete accepted decision: %+v", d)
			}
			if head := testGit(t, f.product, "rev-parse", "HEAD"); head != f.base {
				t.Fatalf("verify changed HEAD to %s", head)
			}
		})
	}
}

func lenGen(patch string) int {
	if patch == "" {
		return 0
	}
	return 1
}

func symlinkService(t *testing.T, dir string) {
	t.Helper()
	service := filepath.Join(dir, "services/secretmanager")
	outside := filepath.Join(dir, "other")
	if err := os.Rename(service, outside); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../other", service); err != nil {
		t.Fatal(err)
	}
}

func replaceWithBinaryPatch(t *testing.T, f fixture, _ []string) {
	t.Helper()
	name := filepath.Join(f.product, stateFile)
	put(t, name, "\x00\x01\x02")
	patch := testGit(t, f.product, "diff", "--binary", "--", stateFile) + "\n"
	put(t, name, "old\n")
	stageInputs(t, f, patch, "", nil)
}
