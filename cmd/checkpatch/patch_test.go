package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/toshi0607/agent-factory/judge/google-cloud-emulator/p0"
)

const writableDir = "services/secretmanager/"

func TestInspectPatch(t *testing.T) {
	repo := t.TempDir()
	if _, err := git(repo, nil, "init", "-q"); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(repo, writableDir), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, writableDir, "binary.go"), []byte{0, 1, 2}, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := git(repo, nil, "add", "--", writableDir+"binary.go"); err != nil {
		t.Fatal(err)
	}
	binaryPatch, err := git(repo, nil, "diff", "--cached", "--binary")
	if err != nil {
		t.Fatal(err)
	}
	link := writableDir + "existing.go"
	if err := os.Symlink("state.go", filepath.Join(repo, link)); err != nil {
		t.Fatal(err)
	}
	if _, err := git(repo, nil, "add", "--", link); err != nil {
		t.Fatal(err)
	}
	tree, err := git(repo, nil, "write-tree")
	if err != nil {
		t.Fatal(err)
	}
	base := strings.TrimSpace(string(tree))

	add := func(name string) string {
		return fmt.Sprintf("diff --git a/%[1]s b/%[1]s\nnew file mode 100644\n--- /dev/null\n+++ b/%[1]s\n@@ -0,0 +1 @@\n+package secretmanager\n", name)
	}
	change := func(header string) string {
		return "diff --git a/" + writableDir + "state.go b/" + writableDir + "state.go\n" + header
	}
	move := func(operation string) string {
		return "diff --git a/" + writableDir + "state.go b/" + writableDir + "renamed.go\n" +
			"similarity index 100%\n" + operation + " from " + writableDir + "state.go\n" +
			operation + " to " + writableDir + "renamed.go\n"
	}
	task, _ := p0.Lookup("sm-create-get")
	for _, tt := range []struct{ name, patch, wantError string }{
		{"allowed", add(writableDir + "new.go"), ""},
		{"allowed space", add(writableDir + "new file.go"), ""},
		{"allowed dots", add(writableDir + "notes..go"), ""},
		{"generated", add(writableDir + "register.gen.go"), "outside"},
		{"generated unimplemented RPC list", add(writableDir + "unimplemented.json"), "outside"},
		{"other service", add("services/pubsub/state.go"), "outside"},
		{"traversal", add(writableDir + "../secretmanager/new.go"), "unsafe"},
		{"absolute", "--- /dev/null\n+++ /" + writableDir + "new.go\n@@ -0,0 +1 @@\n+package secretmanager\n", "unsafe"},
		{"rename", move("rename"), "rename"},
		{"copy", move("copy"), "copy"},
		{"mode change", change("old mode 100644\nnew mode 100755\n"), "mode change"},
		{"delete and recreate with new mode", change("deleted file mode 100644\n--- a/"+writableDir+
			"state.go\n+++ /dev/null\n@@ -1 +0,0 @@\n-old\n") +
			strings.Replace(add(writableDir+"state.go"), "100644", "100755", 1), "mode change"},
		{"new symlink", strings.Replace(add(writableDir+"link.go"), "100644", "120000", 1), "symlink"},
		{"new submodule", strings.Replace(add(writableDir+"module.go"), "100644", "160000", 1), "submodule"},
		{"edit symlink", change("index 1111111..2222222 120000\n--- a/" + writableDir + "state.go\n+++ b/" +
			writableDir + "state.go\n@@ -1 +1 @@\n-old\n+new\n"), "symlink"},
		{"existing symlink without mode", "--- a/" + link + "\n+++ b/" + link + "\n@@ -1 +1 @@\n-state.go\n+other.go\n", "symlink"},
		{"binary", string(binaryPatch), "binary"},
		{"no files", "", "No valid patches"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			code, err := inspectPatch(repo, base, task, []byte(tt.patch))
			if tt.wantError == "" {
				if err != nil || code != 0 {
					t.Fatalf("inspectPatch() = (%d, %v), want (0, nil)", code, err)
				}
			} else if code != 1 || err == nil || !strings.Contains(err.Error(), tt.wantError) {
				t.Fatalf("inspectPatch() = (%d, %v), want exit 1 and an error containing %q", code, err, tt.wantError)
			}
		})
	}
}

func TestValidateRelativePathsAllowsDotsInFilename(t *testing.T) {
	if err := validateRelativePaths([]patchPath{{name: "docs/notes..md"}}); err != nil {
		t.Fatal(err)
	}
}

func TestValidatePaths(t *testing.T) {
	task, _ := p0.Lookup("sm-create-get")
	for _, tt := range []struct {
		name      string
		paths     []patchPath
		wantError string
	}{
		{"empty", nil, "touches no files"},
		{"absolute", []patchPath{{name: "/" + writableDir + "state.go"}}, "unsafe"},
		{"dot-dot", []patchPath{{name: writableDir + "../state.go"}}, "unsafe"},
		{"one forbidden", []patchPath{{name: writableDir + "new.go"}, {name: writableDir + "secret.gen.go"}}, "outside"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := validatePaths(task, tt.paths, "", false)
			if err == nil || !strings.Contains(err.Error(), tt.wantError) {
				t.Fatalf("validatePaths() = %v, want an error containing %q", err, tt.wantError)
			}
		})
	}
}

func TestParseNumstat(t *testing.T) {
	paths, err := parseNumstat([]byte("1\t2\t" + writableDir + "with\ta tab.go\x00-\t-\t" + writableDir + "binary.go\x00"))
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 2 || paths[0] != (patchPath{name: writableDir + "with\ta tab.go"}) ||
		paths[1] != (patchPath{name: writableDir + "binary.go", binary: true}) {
		t.Fatalf("unexpected numstat paths: %+v", paths)
	}
}
