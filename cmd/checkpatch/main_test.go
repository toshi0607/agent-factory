package main

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/toshi0607/agent-factory/poc/record"
)

func TestDockerArgs(t *testing.T) {
	opt := options{taskID: "sm-create-get", image: "image@sha256:fake", modcache: "/module cache", work: "/work",
		p0check: "/factory/bin/p0check", script: "/factory/scripts/p0-check-tree.sh"}
	want := []string{
		"run", "--rm", "--network", "none", "--cap-drop", "ALL",
		"--security-opt", "no-new-privileges", "--pids-limit", "1024", "--memory", "4g",
		"--user", "123:456", "--tmpfs", "/tmp:rw,exec,size=512m",
		"-e", "HOME=/tmp", "-e", "GOCACHE=/gocache", "-e", "GOMODCACHE=/modcache",
		"-e", "GOFLAGS=-mod=readonly", "-e", "GOPROXY=off", "-e", "GOTOOLCHAIN=local",
		"-v", "/work/tree:/tree", "-v", "/work/out:/out", "-v", "/module cache:/modcache",
		"-v", "/work/gocache:/gocache",
		"-v", "/factory/bin/p0check:/p0check:ro", "-v", "/factory/scripts/p0-check-tree.sh:/p0-check-tree.sh:ro",
		"-w", "/tree", "image@sha256:fake", "bash", "/p0-check-tree.sh", "/tree", "sm-create-get", "/p0check", "/out",
	}
	if got := dockerArgs(opt, "/work/tree", "/work/out", 123, 456); !slices.Equal(got, want) {
		t.Fatalf("docker arguments\ngot  %q\nwant %q", got, want)
	}
}

func TestCheckProductArchive(t *testing.T) {
	repo, dir := t.TempDir(), t.TempDir()
	runGit := func(args ...string) string {
		t.Helper()
		got, err := git(repo, nil, args...)
		if err != nil {
			t.Fatal(err)
		}
		return strings.TrimSpace(string(got))
	}
	runGit("init", "--template=")
	writeTestFile(t, filepath.Join(repo, ".gitignore"), "ignored\n", 0o644)
	writeTestFile(t, filepath.Join(repo, "ignored"), "git archive kept this file\n", 0o755)
	if err := os.Symlink("ignored", filepath.Join(repo, "link")); err != nil {
		t.Fatal(err)
	}
	runGit("add", "-f", "-A", "--")
	runGit("-c", gitName, "-c", gitEmail, "commit", "--no-gpg-sign", "-m", "Original baseline")
	archive := filepath.Join(dir, "product.tar.gz")
	runGit("archive", "--format=tar.gz", "-o", archive, "HEAD")

	work := filepath.Join(dir, "work")
	script := filepath.Join(dir, "check.sh")
	writeTestFile(t, script, `set -eu
[[ -x "$1/ignored" && -L "$1/link" ]]
[[ $(git -C "$1" log -1 --format='%an <%ae>') == "checkpatch <checkpatch@invalid>" ]]
[[ $(git -C "$1" rev-list --count HEAD) == 1 ]]
touch "$4/gen-changed-paths.txt" "$4/gen.diff"
git -C "$1" write-tree > "$4/judged-tree.txt"
printf '{"task":"%s","passed":true,"failures":[]}\n' "$2" > "$4/p0check.json"
`, 0o644)
	args := []string{"-product-archive", archive, "-task", "sm-create-get", "-p0check", "fake", "-work", work, "-script", script, "-runner", "direct"}
	out, code := run(append(slices.Clone(args), "-patch", filepath.Join(dir, "missing.diff")), io.Discard)
	if code != 2 || !strings.Contains(out.Error, "read patch") {
		t.Fatalf("missing patch: exit %d, result %+v", code, out)
	}
	out, code = run(append(slices.Clone(args), "-no-patch"), io.Discard)
	if code != 0 || !out.PathsOK || !out.ApplyOK || !out.GenOK || !out.BuildOK || !out.CheckPassed {
		t.Fatalf("archive check: exit %d, result %+v", code, out)
	}
	if out.JudgedTree != runGit("rev-parse", "HEAD^{tree}") || out.GenPatchSHA256 != "" {
		t.Fatalf("archive generation: %+v", out)
	}
	if _, err := os.Stat(filepath.Join(work, "base", ".git")); err != nil {
		t.Fatal(err)
	}
}

func TestCheckScriptGenerationOutputs(t *testing.T) {
	const (
		tree  = "abcdef0123456789abcdef0123456789abcdef01"
		patch = "diff --git a/new.gen.go b/new.gen.go\nnew file mode 100644\n--- /dev/null\n+++ b/new.gen.go\n@@ -0,0 +1 @@\n+generated\n"
		path  = "new.gen.go\n"
	)
	bin := t.TempDir()
	writeTestFile(t, filepath.Join(bin, "docker"), `#!/bin/bash
set -eu
for arg; do
    case "$arg" in
        *:/out) out=${arg%:/out} ;;
    esac
done
cp -RP "$CHECKPATCH_TEST_OUTPUT/." "$out"
exit "$CHECKPATCH_TEST_EXIT"
`, 0o755)
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	for _, tc := range []struct {
		name, gen, paths, treeFile, wantError string
		scriptCode, code                      int
		wantMetadata, omitTree, symlinkPatch  bool
	}{
		{name: "patch", gen: patch, paths: path, treeFile: tree + "\n", wantMetadata: true},
		{name: "no changes without final newline", treeFile: tree, wantMetadata: true},
		{name: "build failure", gen: patch, paths: path, treeFile: tree, scriptCode: 11, code: 1, wantError: "build failed", wantMetadata: true},
		{name: "check failure", gen: patch, paths: path, treeFile: tree, scriptCode: 1, code: 1, wantMetadata: true},
		{name: "unexpected check exit", gen: patch, paths: path, treeFile: tree, scriptCode: 14, code: 2, wantError: "check script exited 14", wantMetadata: true},
		{name: "generation failure", scriptCode: 10, code: 1, omitTree: true, wantError: "generation failed"},
		{name: "snapshot failure", scriptCode: 14, code: 2, omitTree: true, wantError: "read judged tree"},
		{name: "invalid tree ID", treeFile: strings.ToUpper(tree), code: 2, wantError: "40 lowercase hex"},
		{name: "multiple final newlines", treeFile: tree + "\n\n", code: 2, wantError: "40 lowercase hex"},
		{name: "oversized tree file", treeFile: strings.Repeat("a", 65), code: 2, wantError: "exceeds 64 bytes"},
		{name: "missing tree file", omitTree: true, code: 2, wantError: "read judged tree"},
		{name: "oversized patch", gen: strings.Repeat("a", maxGeneratedPatchSize+1), paths: path, treeFile: tree, code: 2, wantError: "exceeds 5242880 bytes"},
		{name: "patch symlink", gen: patch, paths: path, treeFile: tree, symlinkPatch: true, code: 2, wantError: "expected regular output file"},
		{name: "missing paths", gen: patch, treeFile: tree, code: 2, wantError: "inconsistent generated patch"},
		{name: "unexpected paths", paths: path, treeFile: tree, code: 2, wantError: "inconsistent generated patch"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture := t.TempDir()
			t.Setenv("CHECKPATCH_TEST_OUTPUT", fixture)
			t.Setenv("CHECKPATCH_TEST_EXIT", fmt.Sprint(tc.scriptCode))
			writeTestFile(t, filepath.Join(fixture, "gen-changed-paths.txt"), tc.paths, 0o644)
			genFile := filepath.Join(fixture, "gen.diff")
			if tc.symlinkPatch {
				if err := os.Symlink("gen-changed-paths.txt", genFile); err != nil {
					t.Fatal(err)
				}
			} else {
				writeTestFile(t, genFile, tc.gen, 0o644)
			}
			if !tc.omitTree {
				writeTestFile(t, filepath.Join(fixture, "judged-tree.txt"), tc.treeFile, 0o644)
			}
			p0 := filepath.Join(fixture, "p0check.json")
			switch tc.scriptCode {
			case 0:
				writeTestFile(t, p0, `{"task":"sm-create-get","passed":true,"failures":[]}`, 0o644)
			case 1:
				writeTestFile(t, p0, `{"task":"sm-create-get","passed":false,"failures":[{"name":"get","message":"failed"}]}`, 0o644)
			}

			opt := options{runner: "docker", work: t.TempDir(), taskID: "sm-create-get"}
			output := filepath.Join(opt.work, "out")
			out := record.CheckResult{}
			code, err := runCheckScript(opt, filepath.Join(opt.work, "tree"), output, &out)
			if code != tc.code || (err == nil) != (tc.wantError == "") || (err != nil && !strings.Contains(err.Error(), tc.wantError)) {
				t.Fatalf("runCheckScript = (%d, %v), want (%d, %q)", code, err, tc.code, tc.wantError)
			}
			wantTree, wantHash := "", ""
			if tc.wantMetadata {
				wantTree = tree
			}
			artifact := filepath.Join(output, "gen-patch.diff")
			if tc.wantMetadata && tc.gen != "" {
				wantHash = fmt.Sprintf("%x", sha256.Sum256([]byte(tc.gen)))
				data, err := os.ReadFile(artifact)
				if err != nil || string(data) != tc.gen || !slices.Equal(out.GenChangedPaths, []string{strings.TrimSuffix(tc.paths, "\n")}) {
					t.Fatalf("generated patch artifact or paths differ: file %v, paths %q", err, out.GenChangedPaths)
				}
			} else if _, err := os.Lstat(artifact); !os.IsNotExist(err) {
				t.Fatalf("unexpected generated patch artifact: %v", err)
			}
			if out.JudgedTree != wantTree || out.GenPatchSHA256 != wantHash {
				t.Fatalf("unexpected generation metadata: %+v", out)
			}
			if out.GenOK != tc.wantMetadata || out.BuildOK != (tc.wantMetadata && tc.scriptCode != 11) || out.CheckPassed != (tc.code == 0) {
				t.Fatalf("unexpected judge status: %+v", out)
			}
		})
	}
}

func TestArchiveEntryPaths(t *testing.T) {
	for _, name := range []string{"/absolute", "nested/../escape", ".git/config", "notes..md"} {
		t.Run(name, func(t *testing.T) {
			file, err := os.Create(filepath.Join(t.TempDir(), "product.tar.gz"))
			if err != nil {
				t.Fatal(err)
			}
			z := gzip.NewWriter(file)
			archive := tar.NewWriter(z)
			if err := archive.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o644}); err != nil {
				t.Fatal(err)
			}
			for _, close := range []func() error{archive.Close, z.Close, file.Close} {
				if err := close(); err != nil {
					t.Fatal(err)
				}
			}
			base := t.TempDir()
			err = extractArchive(file.Name(), base)
			if name == "notes..md" {
				if err != nil {
					t.Fatal(err)
				}
				if _, err := os.Stat(filepath.Join(base, name)); err != nil {
					t.Fatal(err)
				}
			} else if err == nil || !strings.Contains(err.Error(), "unsafe archive path") {
				t.Fatalf("unsafe archive path accepted: %v", err)
			}
		})
	}
}

func writeTestFile(t *testing.T, path, contents string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(contents), mode); err != nil {
		t.Fatal(err)
	}
}

func TestCheckRequiresRunner(t *testing.T) {
	result, code := run([]string{"-product", "test", "-task", "sm-create-get", "-p0check", "test", "-work", "test", "-no-patch"}, io.Discard)
	if code != 2 || result.Error != "invalid arguments" {
		t.Fatalf("missing runner: exit %d, result %+v", code, result)
	}
}
