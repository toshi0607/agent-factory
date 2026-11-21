package main

import (
	"archive/tar"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
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
touch "$4/gen-changed-paths.txt"
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
	if _, err := os.Stat(filepath.Join(work, "base", ".git")); err != nil {
		t.Fatal(err)
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
