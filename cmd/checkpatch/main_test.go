package main

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestDockerArgs(t *testing.T) {
	opt := options{taskID: "sm-create-get", image: "image@sha256:fake", modcache: "/module cache", work: "/work",
		p0check: "/factory/bin/p0check", script: "/factory/scripts/p0-check-tree.sh", genScript: "/factory/scripts/p0-gen-tree.sh"}
	common := []string{
		"run", "--rm", "--network", "none", "--cap-drop", "ALL",
		"--security-opt", "no-new-privileges", "--pids-limit", "1024", "--memory", "4g",
		"--user", "123:456", "--tmpfs", "/tmp:rw,exec,size=512m",
		"-e", "HOME=/tmp", "-e", "GOCACHE=/gocache", "-e", "GOMODCACHE=/modcache",
		"-e", "GOFLAGS=-mod=readonly", "-e", "GOPROXY=off", "-e", "GOTOOLCHAIN=local",
	}
	wantCheck := append(slices.Clone(common),
		"-v", "/work/out:/out", "-v", "/work/gocache:/gocache", "-w", "/tree",
		"-v", "/work/tree:/tree:ro", "-v", "/module cache:/modcache:ro",
		"-v", "/factory/bin/p0check:/p0check:ro", "-v", "/factory/scripts/p0-check-tree.sh:/p0-check-tree.sh:ro",
		"image@sha256:fake", "bash", "/p0-check-tree.sh", "/tree", "sm-create-get", "/p0check", "/out",
	)
	if got := dockerArgs(opt, false, "/work/tree", "/work/out", 123, 456); !slices.Equal(got, wantCheck) {
		t.Fatalf("check Docker arguments\ngot  %q\nwant %q", got, wantCheck)
	}
	wantGen := append(common,
		"-v", "/work/gen-out:/out", "-v", "/work/gen-gocache:/gocache", "-w", "/tree",
		"-v", "/work/tree:/tree", "-v", "/module cache:/modcache:ro",
		"-v", "/factory/scripts/p0-gen-tree.sh:/p0-gen-tree.sh:ro",
		"image@sha256:fake", "bash", "/p0-gen-tree.sh", "/tree", "/out",
	)
	if got := dockerArgs(opt, true, "/work/tree", "/work/gen-out", 123, 456); !slices.Equal(got, wantGen) {
		t.Fatalf("generation Docker arguments\ngot  %q\nwant %q", got, wantGen)
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
	runGit("add", "-f", "-A", "--")
	runGit("-c", gitName, "-c", gitEmail, "commit", "--no-gpg-sign", "-m", "Original baseline")
	archive := filepath.Join(dir, "product.tar.gz")
	runGit("archive", "--format=tar.gz", "-o", archive, "HEAD")

	work := filepath.Join(dir, "work")
	genScript := filepath.Join(dir, "gen.sh")
	writeTestFile(t, genScript, `set -eu
[[ -x "$1/ignored" && ! -e "$1/.git" ]]
touch "$2/generated"
`, 0o644)
	script := filepath.Join(dir, "check.sh")
	writeTestFile(t, script, `set -eu
[[ -x "$1/ignored" && ! -e "$1/.git" && ! -e "$4/generated" ]]
printf '{"task":"%s","passed":true,"failures":[]}\n' "$2" > "$4/p0check.json"
`, 0o644)
	args := []string{"-product-archive", archive, "-task", "sm-create-get", "-p0check", "fake", "-work", work, "-gen-script", genScript, "-script", script, "-runner", "direct"}
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
	base := filepath.Join(work, "base")
	if got := string(testGit(t, base, "log", "-1", "--format=%an <%ae>")); got != "checkpatch <checkpatch@invalid>\n" {
		t.Fatalf("archive baseline author = %q", got)
	}
	if got := string(testGit(t, base, "rev-list", "--count", "HEAD")); got != "1\n" {
		t.Fatalf("archive baseline commit count = %q", got)
	}
}

func TestCheckTreeScriptsDirect(t *testing.T) {
	product, bin := t.TempDir(), t.TempDir()
	testGit(t, product, "init", "--template=")
	writeTestFile(t, filepath.Join(product, "Makefile"), `gen-only:
	test ! -e .git
	test "$$GOPROXY" = off && test "$$GOTOOLCHAIN" = local && test "$$GOSUMDB" = off
	echo generated > output.gen.go
	test "$$TEST_GEN_FAIL" != yes
`, 0o644)
	testGit(t, product, "add", "-A", "--")
	testGit(t, product, "-c", gitName, "-c", gitEmail, "commit", "--no-gpg-sign", "-m", "Product")
	writeTestFile(t, filepath.Join(bin, "go"), `#!/bin/bash
set -eu
[[ $1 == build && $2 == -buildvcs=false && $3 == -o && $5 == ./cmd/google-cloud-emulator ]]
[[ ! -e .git && $(cat output.gen.go) == generated ]]
cat > "$4" <<'EMULATOR'
#!/bin/bash
printf '%s\n' 'google-cloud-emulator listening on 127.0.0.1:12345'
exec sleep 30
EMULATOR
chmod +x "$4"
`, 0o755)
	p0check := filepath.Join(bin, "p0check")
	writeTestFile(t, p0check, `#!/bin/bash
set -eu
[[ $1 == -task && $2 == sm-create-get && $3 == -addr && $4 == 127.0.0.1:12345 ]]
printf '{"task":"%s","passed":true,"failures":[]}\n' "$2"
`, 0o755)
	t.Setenv("GOPROXY", "https://unused.invalid")
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))

	for _, tc := range []struct {
		name, fail string
		code       int
	}{
		{"generates and checks", "no", 0},
		{"make failure", "yes", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("TEST_GEN_FAIL", tc.fail)
			work := t.TempDir()
			out, code := run([]string{"-runner", "direct", "-product", product, "-no-patch", "-task", "sm-create-get",
				"-work", work, "-p0check", p0check, "-gen-script", "../../scripts/p0-gen-tree.sh", "-script", "../../scripts/p0-check-tree.sh"}, io.Discard)
			passed := tc.code == 0
			if code != tc.code || out.GenOK != passed || out.BuildOK != passed || out.CheckPassed != passed {
				t.Fatalf("run = (%d, %+v), want exit %d", code, out, tc.code)
			}
			if log, err := os.ReadFile(filepath.Join(work, "gen-out", "gen.log")); err != nil || !strings.Contains(string(log), "echo generated") {
				t.Fatalf("generation log = %q, error = %v", log, err)
			}
			if passed && !slices.Equal(out.GenChangedPaths, []string{"output.gen.go"}) {
				t.Fatalf("unexpected generation paths: %q", out.GenChangedPaths)
			}
		})
	}
}

func TestGenerationScriptInfrastructureErrors(t *testing.T) {
	tree := t.TempDir()
	blockedOut := filepath.Join(t.TempDir(), "file")
	writeTestFile(t, blockedOut, "not a directory", 0o644)
	for _, args := range [][]string{nil, {filepath.Join(tree, "missing"), t.TempDir()}, {tree, blockedOut}} {
		cmd := exec.CommandContext(t.Context(), "bash", append([]string{"../../scripts/p0-gen-tree.sh"}, args...)...)
		if log, err := cmd.CombinedOutput(); err == nil || cmd.ProcessState.ExitCode() != 14 {
			t.Fatalf("generation script with %q: expected exit 14, got %v with %s", args, err, log)
		}
	}
}

func TestCheckScriptGenerationOutputs(t *testing.T) {
	product, bin := t.TempDir(), t.TempDir()
	testGit(t, product, "init", "--template=")
	writeTestFile(t, filepath.Join(product, ".gitignore"), "new.gen.go\n", 0o644)
	writeTestFile(t, filepath.Join(product, ".gitattributes"), "*.go text eol=lf\n", 0o644)
	for _, name := range []string{"delete.gen.go", "modify.gen.go"} {
		writeTestFile(t, filepath.Join(product, name), "old\n", 0o644)
	}
	if err := os.MkdirAll(filepath.Join(product, writableDir), 0o755); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(product, writableDir, "state.go"), "old\n", 0o644)
	testGit(t, product, "add", "-A", "--")
	testGit(t, product, "-c", gitName, "-c", gitEmail, "commit", "--no-gpg-sign", "-m", "Product")

	rolePatch := filepath.Join(t.TempDir(), "role.diff")
	writeTestFile(t, filepath.Join(product, writableDir, "state.go"), "role\n", 0o644)
	writeTestFile(t, rolePatch, string(testGit(t, product, "diff", "--")), 0o644)
	want := filepath.Join(t.TempDir(), "want")
	testGit(t, product, "clone", "--no-hardlinks", "--", product, want)
	role, err := os.ReadFile(rolePatch)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := git(want, role, "apply", "--index", "--"); err != nil {
		t.Fatal(err)
	}
	testGit(t, want, "-c", gitName, "-c", gitEmail, "commit", "--no-gpg-sign", "-m", "Role")
	roleTree := strings.TrimSpace(string(testGit(t, want, "rev-parse", "HEAD^{tree}")))
	writeTestFile(t, filepath.Join(want, "new.gen.go"), "added\n", 0o644)
	writeTestFile(t, filepath.Join(want, "modify.gen.go"), "modified\n", 0o644)
	if err := os.Remove(filepath.Join(want, "delete.gen.go")); err != nil {
		t.Fatal(err)
	}
	testGit(t, want, "add", "-f", "-A", "--")
	wantTree := strings.TrimSpace(string(testGit(t, want, "write-tree")))
	wantPatch := testGit(t, want, "diff", "--cached", "--binary", "--no-ext-diff", "--no-textconv", "--no-renames", "HEAD", "--")
	wantHash := fmt.Sprintf("%x", sha256.Sum256(wantPatch))
	wantPaths := []string{"delete.gen.go", "modify.gen.go", "new.gen.go"}

	writeTestFile(t, filepath.Join(bin, "docker"), `#!/bin/bash
set -eu
for arg; do
    case "$arg" in
        *:/out) out=${arg%:/out} ;;
        *:/tree) tree=${arg%:/tree}; phase=gen ;;
        *:/tree:ro) tree=${arg%:/tree:ro}; phase=check ;;
    esac
done
[[ ! -e "$tree/.git" && ! -L "$tree/.git" ]]
[[ $(cat "$tree/services/secretmanager/state.go") == role ]]
if [[ $phase == gen ]]; then
    case "$TEST_GEN_ACTION" in
        change)
            printf 'added\n' > "$tree/new.gen.go"
            printf 'modified\n' > "$tree/modify.gen.go"
            rm "$tree/delete.gen.go"
            ;;
        dotgit) mkdir "$tree/.git" ;;
        nested-dotgit) mkdir -p "$tree/nested/.GiT" ;;
        symlink) ln -s /no-such-path "$tree/link" ;;
        fifo) mkfifo "$tree/pipe" ;;
        large) head -c 5242881 /dev/zero | tr '\000' a > "$tree/large.gen.go" ;;
    esac
    printf 'forged generation output\n' > "$out/gen.diff"
    exit "$TEST_GEN_EXIT"
fi
touch "$TEST_CHECK_RAN"
if [[ "$TEST_CHECK_TAMPER" == true ]]; then
    printf 'role\r\n' > "$tree/services/secretmanager/state.go"
fi
case "$TEST_CHECK_METADATA" in
    fake)
        printf '%s\n' 'ffffffffffffffffffffffffffffffffffffffff' > "$out/judged-tree.txt"
        printf '%s\n' 'fake.gen.go' > "$out/gen-changed-paths.txt"
        printf '%s\n' 'forged patch' > "$out/gen.diff"
        printf '%s\n' 'forged artifact' > "$out/gen-patch.diff"
        ;;
    invalid-tree) printf 'NOT A TREE\n' > "$out/judged-tree.txt" ;;
    multiline-tree) printf 'tree\n\n' > "$out/judged-tree.txt" ;;
    oversized-tree) head -c 65 /dev/zero > "$out/judged-tree.txt" ;;
    patch-symlink) ln -s /no-such-path "$out/gen.diff" ;;
    paths-alone) printf 'fake.gen.go\n' > "$out/gen-changed-paths.txt" ;;
    patch-alone) printf 'forged patch\n' > "$out/gen.diff" ;;
esac
case "$TEST_CHECK_EXIT" in
    0) printf '%s\n' '{"task":"sm-create-get","passed":true,"failures":[]}' > "$out/p0check.json" ;;
    1) printf '%s\n' '{"task":"sm-create-get","passed":false,"failures":[{"name":"get","message":"failed"}]}' > "$out/p0check.json" ;;
esac
exit "$TEST_CHECK_EXIT"
`, 0o755)
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))

	for _, tc := range []struct {
		name, gen, metadata, wantError string
		genExit, checkExit, code       int
		snapshot, build, tamper        bool
	}{
		{name: "patch", gen: "change", metadata: "fake", snapshot: true, build: true},
		{name: "no changes", snapshot: true, build: true},
		{name: "build failure", gen: "change", checkExit: 11, code: 1, wantError: "build failed", snapshot: true},
		{name: "check failure", gen: "change", checkExit: 1, code: 1, snapshot: true, build: true},
		{name: "emulator startup failure", checkExit: 12, code: 1, wantError: "emulator did not announce", snapshot: true, build: true},
		{name: "p0check infrastructure failure", checkExit: 13, code: 1, wantError: "p0check could not run", snapshot: true, build: true},
		{name: "unexpected check exit", gen: "change", checkExit: 14, code: 2, wantError: "check script exited 14", snapshot: true},
		{name: "generation failure", gen: "change", genExit: 10, code: 1, wantError: "generation failed"},
		{name: "generation infrastructure failure", gen: "change", genExit: 14, code: 2, wantError: "generation script exited 14"},
		{name: "invalid check tree ID ignored", metadata: "invalid-tree", snapshot: true, build: true},
		{name: "multiple final newlines in check tree ID ignored", metadata: "multiline-tree", snapshot: true, build: true},
		{name: "oversized check tree file ignored", metadata: "oversized-tree", snapshot: true, build: true},
		{name: "missing check tree file ignored", gen: "change", snapshot: true, build: true},
		{name: "oversized patch", gen: "large", code: 2, wantError: "exceeds 5242880 bytes"},
		{name: "check patch symlink ignored", metadata: "patch-symlink", snapshot: true, build: true},
		{name: "missing check paths ignored", metadata: "patch-alone", snapshot: true, build: true},
		{name: "unexpected check paths ignored", metadata: "paths-alone", snapshot: true, build: true},
		{name: "generation creates symlink", gen: "symlink", code: 2, wantError: "not a regular file or directory"},
		{name: "generation creates FIFO", gen: "fifo", code: 2, wantError: "not a regular file or directory"},
		{name: "generation creates .git", gen: "dotgit", code: 2, wantError: "worktree contains a .git entry"},
		{name: "generation creates nested .git", gen: "nested-dotgit", code: 2, wantError: "worktree contains a .git entry"},
		{name: "check changes worktree bytes", tamper: true, code: 2, wantError: "worktree changed during check", snapshot: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			work := t.TempDir()
			checkRan := filepath.Join(work, "ran-check")
			t.Setenv("TEST_GEN_ACTION", tc.gen)
			t.Setenv("TEST_GEN_EXIT", fmt.Sprint(tc.genExit))
			t.Setenv("TEST_CHECK_EXIT", fmt.Sprint(tc.checkExit))
			t.Setenv("TEST_CHECK_METADATA", tc.metadata)
			t.Setenv("TEST_CHECK_TAMPER", fmt.Sprint(tc.tamper))
			t.Setenv("TEST_CHECK_RAN", checkRan)

			out, code := run([]string{"-runner", "docker", "-product", product, "-patch", rolePatch,
				"-task", "sm-create-get", "-p0check", "fake", "-work", work, "-image", "fake", "-modcache", bin}, io.Discard)
			if code != tc.code || (out.Error == "") != (tc.wantError == "") || !strings.Contains(out.Error, tc.wantError) {
				t.Fatalf("run = (%d, %+v), want exit %d and error %q", code, out, tc.code, tc.wantError)
			}
			if !out.PathsOK || !out.ApplyOK || out.GenOK != tc.snapshot || out.BuildOK != tc.build || out.CheckPassed != (tc.code == 0) {
				t.Fatalf("unexpected judge status: %+v", out)
			}
			if _, err := os.Stat(checkRan); (tc.snapshot && err != nil) || (!tc.snapshot && !os.IsNotExist(err)) {
				t.Fatalf("check phase marker: %v, want presence %t", err, tc.snapshot)
			}
			file := filepath.Join(work, "gen-patch.diff")
			patch, err := os.ReadFile(file)
			switch {
			case !tc.snapshot:
				if out.JudgedTree != "" || out.GenPatchSHA256 != "" || len(out.GenChangedPaths) != 0 || !os.IsNotExist(err) {
					t.Fatalf("metadata after failed generation or snapshot: %+v, artifact error: %v", out, err)
				}
			case tc.gen == "change":
				if err != nil || string(patch) != string(wantPatch) || out.JudgedTree != wantTree ||
					out.GenPatchSHA256 != wantHash || !slices.Equal(out.GenChangedPaths, wantPaths) {
					t.Fatalf("unexpected generated snapshot: %+v, patch %q, error %v", out, patch, err)
				}
			default:
				if out.JudgedTree != roleTree || out.GenPatchSHA256 != "" || len(out.GenChangedPaths) != 0 || !os.IsNotExist(err) {
					t.Fatalf("unexpected no-change snapshot: %+v, artifact error: %v", out, err)
				}
			}
		})
	}
}

func testGit(t *testing.T, dir string, args ...string) []byte {
	t.Helper()
	data, err := git(dir, nil, args...)
	if err != nil {
		t.Fatal(err)
	}
	return data
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
