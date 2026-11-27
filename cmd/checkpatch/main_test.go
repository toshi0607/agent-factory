package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestDockerArgs(t *testing.T) {
	opt := options{taskID: "sm-create-get", image: "image@sha256:fake", modcache: "/module cache", work: "/work",
		p0check: "/factory/bin/p0check", genScript: "/factory/scripts/p0-gen-tree.sh", buildScript: "/factory/scripts/p0-build-tree.sh"}
	hardening := []string{
		"--cap-drop", "ALL",
		"--security-opt", "no-new-privileges", "--pids-limit", "1024", "--memory", "4g",
		"--user", "123:456",
	}
	goEnv := []string{
		"--tmpfs", "/tmp:rw,exec,size=512m",
		"-e", "HOME=/tmp", "-e", "GOCACHE=/gocache", "-e", "GOMODCACHE=/modcache",
		"-e", "GOFLAGS=-mod=readonly", "-e", "GOPROXY=off", "-e", "GOTOOLCHAIN=local",
	}
	wantBuild := slices.Concat([]string{"run", "--rm", "--network", "none", "--name", "build"}, hardening, goEnv, []string{
		"-v", "/work/build-out:/out", "-v", "/work/gocache:/gocache", "-w", "/tree",
		"-v", "/work/tree:/tree:ro", "-v", "/module cache:/modcache:ro",
		"-v", "/factory/scripts/p0-build-tree.sh:/p0-build-tree.sh:ro",
		"image@sha256:fake", "bash", "/p0-build-tree.sh", "/tree", "/out",
	})
	if got := buildDockerArgs(opt, "/work/tree", "/work/build-out", "build", 123, 456); !slices.Equal(got, wantBuild) {
		t.Fatalf("build Docker arguments\ngot  %q\nwant %q", got, wantBuild)
	}
	wantGen := slices.Concat([]string{"run", "--rm", "--network", "none"}, hardening, goEnv, []string{
		"-v", "/work/gen-out:/out", "-v", "/work/gen-gocache:/gocache", "-w", "/tree",
		"-v", "/work/tree:/tree", "-v", "/module cache:/modcache:ro",
		"-v", "/factory/scripts/p0-gen-tree.sh:/p0-gen-tree.sh:ro",
		"image@sha256:fake", "bash", "/p0-gen-tree.sh", "/tree", "/out",
	})
	if got := generationDockerArgs(opt, "/work/tree", "/work/gen-out", 123, 456); !slices.Equal(got, wantGen) {
		t.Fatalf("generation Docker arguments\ngot  %q\nwant %q", got, wantGen)
	}
	wantProduct := slices.Concat([]string{"run", "--detach", "--name", "emulator", "--network", "isolated", "--network-alias", "product"}, hardening, []string{
		"--read-only", "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=16m",
		"--log-driver", "local", "--log-opt", "max-size=1m", "--log-opt", "max-file=1", "--log-opt", "compress=false",
		"-v", "/work/build-out:/product:ro", "--entrypoint", "/product/emulator",
		"image@sha256:fake", "-addr", "0.0.0.0:8080",
	})
	if got := productDockerArgs(opt, "/work/build-out", "isolated", "emulator", 123, 456); !slices.Equal(got, wantProduct) {
		t.Fatalf("product Docker arguments\ngot  %q\nwant %q", got, wantProduct)
	}
	wantJudge := slices.Concat([]string{"run", "--rm", "--name", "judge", "--network", "isolated"}, hardening, []string{
		"-v", "/factory/bin/p0check:/p0check:ro", "-v", "/work/judge-out:/out", "--entrypoint", "/p0check",
		"image@sha256:fake", "-task", "sm-create-get", "-addr", "product:8080", "-wait", "30s",
	})
	if got := judgeDockerArgs(opt, "/work/judge-out", "isolated", "judge", 123, 456); !slices.Equal(got, wantJudge) {
		t.Fatalf("judge Docker arguments\ngot  %q\nwant %q", got, wantJudge)
	}
	for _, tc := range []struct {
		name      string
		args      []string
		forbidden []string
	}{
		{"product", wantProduct, []string{"/work/tree", "/module cache", "/factory/bin/p0check", "/work/judge-out", "/work/product-out"}},
		{"judge", wantJudge, []string{"/work/tree", "/module cache", "/work/build-out"}},
	} {
		for i, arg := range tc.args {
			if arg != "-v" || i+1 >= len(tc.args) {
				continue
			}
			for _, source := range tc.forbidden {
				if strings.HasPrefix(tc.args[i+1], source+":") {
					t.Fatalf("%s container mounts %q", tc.name, tc.args[i+1])
				}
			}
		}
		if slices.Contains(tc.args, "host") || slices.Contains(tc.args, "bridge") || slices.Contains(tc.args, "-p") || slices.Contains(tc.args, "--publish") {
			t.Fatalf("%s container is not confined to the internal network: %q", tc.name, tc.args)
		}
	}
	if !slices.Contains(wantProduct, "--read-only") {
		t.Fatalf("product container root filesystem is writable: %q", wantProduct)
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
	out, code := run(t.Context(), append(slices.Clone(args), "-patch", filepath.Join(dir, "missing.diff")), io.Discard)
	if code != 2 || !strings.Contains(out.Error, "read patch") {
		t.Fatalf("missing patch: exit %d, result %+v", code, out)
	}
	out, code = run(t.Context(), append(slices.Clone(args), "-no-patch"), io.Discard)
	if code != 0 || out.Runner != "direct" || !out.PathsOK || !out.ApplyOK || !out.GenOK || !out.BuildOK || !out.CheckPassed {
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
			out, code := run(t.Context(), []string{"-runner", "direct", "-product", product, "-no-patch", "-task", "sm-create-get",
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

func TestBuildTreeScript(t *testing.T) {
	tree, bin := t.TempDir(), t.TempDir()
	writeTestFile(t, filepath.Join(bin, "go"), `#!/bin/bash
set -eu
[[ $# == 5 && $1 == build && $2 == -buildvcs=false && $3 == -o && $5 == ./cmd/google-cloud-emulator ]]
[[ "$PWD" -ef "$TEST_BUILD_TREE" && "$GOPROXY" == off && "$GOTOOLCHAIN" == local && "$GONOPROXY" == none && "$GOSUMDB" == off ]]
printf 'build log\n' >&2
[[ $TEST_BUILD_FAIL == no ]] || exit 1
printf 'built emulator\n' > "$4"
`, 0o755)
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("GOPROXY", "https://unused.invalid")
	t.Setenv("TEST_BUILD_TREE", tree)
	for _, tc := range []struct {
		name, fail string
		code       int
	}{
		{"success", "no", 0},
		{"build failed", "yes", 11},
		{"missing tree", "no", 14},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("TEST_BUILD_FAIL", tc.fail)
			out, src := t.TempDir(), tree
			if tc.code == 14 {
				src = filepath.Join(tree, "missing")
			}
			cmd := exec.CommandContext(t.Context(), "bash", "../../scripts/p0-build-tree.sh", src, out)
			if log, err := cmd.CombinedOutput(); cmd.ProcessState.ExitCode() != tc.code {
				t.Fatalf("build script: expected exit %d, got %v with %s", tc.code, err, log)
			}
			if tc.code != 14 {
				if log, err := os.ReadFile(filepath.Join(out, "build.log")); err != nil || string(log) != "build log\n" {
					t.Fatalf("build.log = %q, error = %v", log, err)
				}
			}
			if tc.code == 0 {
				if binary, err := os.ReadFile(filepath.Join(out, "emulator")); err != nil || string(binary) != "built emulator\n" {
					t.Fatalf("build output = %q, error = %v", binary, err)
				}
			}
		})
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
printf '%s\0' "$@" >> "$TEST_DOCKER_TRACE"
printf '\0' >> "$TEST_DOCKER_TRACE"
case "$1" in
    logs)
        if [[ $TEST_LARGE_LOGS == true ]]; then
            head -c 1048580 /dev/zero | tr '\000' a
            head -c 1048580 /dev/zero | tr '\000' b >&2
        fi
        exit 0
        ;;
    network)
        if [[ $2 == rm && $TEST_CLEANUP_FAIL == true ]]; then
            printf 'test network removal failure\n' >&2
            exit 1
        fi
        exit 0
        ;;
    kill|rm) exit 0 ;;
esac

for arg; do
    case "$arg" in
        *:/out) out=${arg%:/out} ;;
        *:/tree) tree=${arg%:/tree}; phase=gen ;;
        *:/tree:ro) tree=${arg%:/tree:ro}; phase=build ;;
        /p0check) phase=judge ;;
        /product/emulator) phase=product ;;
    esac
done
if [[ $phase == gen || $phase == build ]]; then
    [[ ! -e "$tree/.git" && ! -L "$tree/.git" ]]
    [[ $(cat "$tree/services/secretmanager/state.go") == role ]]
fi
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
if [[ $phase == build ]]; then
    if [[ $TEST_CHECK_TAMPER == true ]]; then
        printf 'role\r\n' > "$tree/services/secretmanager/state.go"
    fi
    if [[ $TEST_CHECK_METADATA == forged-verdicts ]]; then
        printf '%s\n' '{"task":"sm-create-get","passed":true,"failures":[]}' > "$out/p0check.json"
    fi
    exit "$TEST_BUILD_EXIT"
fi
if [[ $phase == product ]]; then
    if [[ $TEST_CHECK_METADATA == forged-verdicts ]]; then
        printf '%s\n' '{"task":"sm-create-get","passed":true,"failures":[]}' > "$TEST_WORK/product-out/p0check.json"
    fi
    exit "$TEST_PRODUCT_EXIT"
fi
if [[ $TEST_CANCEL == true ]]; then
    touch "$TEST_WORK/judge-started"
    exec sleep 30
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
    0) printf '%s\n' '{"task":"sm-create-get","passed":true,"failures":[]}' ;;
    1) printf '%s\n' '{"task":"sm-create-get","passed":false,"failures":[{"name":"get","message":"failed"}]}' ;;
esac
exit "$TEST_CHECK_EXIT"
`, 0o755)
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))

	for _, tc := range []struct {
		name, gen, metadata, wantError  string
		genExit, buildExit, productExit int
		checkExit, code                 int
		snapshot, build, tamper         bool
		cancel, cleanupFail, largeLogs  bool
	}{
		{name: "patch", gen: "change", metadata: "fake", snapshot: true, build: true},
		{name: "no changes", snapshot: true, build: true},
		{name: "build failure", gen: "change", buildExit: 11, code: 1, wantError: "build failed", snapshot: true},
		{name: "build infrastructure failure", buildExit: 14, code: 2, wantError: "build container exited 14", snapshot: true},
		{name: "check failure", gen: "change", checkExit: 1, code: 1, snapshot: true, build: true},
		{name: "emulator startup failure", productExit: 126, code: 1, wantError: "product container could not run", snapshot: true, build: true},
		{name: "Docker startup failure", productExit: 125, code: 2, wantError: "start product container: docker exited 125", snapshot: true, build: true},
		{name: "p0check infrastructure failure", checkExit: 2, code: 1, wantError: "p0check could not run", snapshot: true, build: true},
		{name: "unexpected check exit", gen: "change", checkExit: 14, code: 2, wantError: "judge container exited 14", snapshot: true, build: true},
		{name: "forged verdicts ignored", metadata: "forged-verdicts", checkExit: 1, code: 1, snapshot: true, build: true},
		{name: "cleanup failure preserves verdict", cleanupFail: true, snapshot: true, build: true},
		{name: "product logs capped", largeLogs: true, snapshot: true, build: true},
		{name: "cancel during judge", cancel: true, code: 2, wantError: "context canceled", snapshot: true, build: true},
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
		{name: "check changes worktree bytes", tamper: true, code: 2, wantError: "worktree changed during check", snapshot: true, build: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			work := t.TempDir()
			trace := filepath.Join(work, "docker-trace")
			t.Setenv("TEST_GEN_ACTION", tc.gen)
			t.Setenv("TEST_GEN_EXIT", fmt.Sprint(tc.genExit))
			t.Setenv("TEST_BUILD_EXIT", fmt.Sprint(tc.buildExit))
			t.Setenv("TEST_PRODUCT_EXIT", fmt.Sprint(tc.productExit))
			t.Setenv("TEST_CHECK_EXIT", fmt.Sprint(tc.checkExit))
			t.Setenv("TEST_CHECK_METADATA", tc.metadata)
			t.Setenv("TEST_CHECK_TAMPER", fmt.Sprint(tc.tamper))
			t.Setenv("TEST_DOCKER_TRACE", trace)
			t.Setenv("TEST_WORK", work)
			t.Setenv("TEST_CANCEL", fmt.Sprint(tc.cancel))
			t.Setenv("TEST_CLEANUP_FAIL", fmt.Sprint(tc.cleanupFail))
			t.Setenv("TEST_LARGE_LOGS", fmt.Sprint(tc.largeLogs))

			ctx, stop := context.WithTimeout(t.Context(), 10*time.Second)
			defer stop()
			if tc.cancel {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				defer cancel()
				go func(waitCtx context.Context) {
					tick := time.NewTicker(10 * time.Millisecond)
					defer tick.Stop()
					for {
						if _, err := os.Stat(filepath.Join(work, "judge-started")); err == nil {
							cancel()
							return
						}
						select {
						case <-waitCtx.Done():
							return
						case <-tick.C:
						}
					}
				}(ctx)
			}
			opt := options{taskID: "sm-create-get", work: work, p0check: filepath.Join(bin, "fake"), image: "fake", modcache: bin,
				genScript: filepath.Join(bin, "gen.sh"), buildScript: filepath.Join(bin, "build.sh")}
			var stderr bytes.Buffer
			out, code := run(ctx, []string{"-runner", "docker", "-product", product, "-patch", rolePatch,
				"-task", opt.taskID, "-p0check", opt.p0check, "-work", work, "-image", opt.image,
				"-modcache", bin, "-gen-script", opt.genScript, "-build-script", opt.buildScript}, &stderr)
			if code != tc.code || (out.Error == "") != (tc.wantError == "") || !strings.Contains(out.Error, tc.wantError) {
				t.Fatalf("run = (%d, %+v), want exit %d and error %q", code, out, tc.code, tc.wantError)
			}
			if out.Runner != "docker" || !out.PathsOK || !out.ApplyOK || out.GenOK != tc.snapshot || out.BuildOK != tc.build || out.CheckPassed != (tc.code == 0) {
				t.Fatalf("unexpected judge status: %+v", out)
			}
			if tc.checkExit == 1 && (len(out.Failures) != 1 || out.Failures[0].Name != "get") {
				t.Fatalf("unexpected failures: %+v", out.Failures)
			}
			if strings.Contains(stderr.String(), "test network removal failure") != tc.cleanupFail {
				t.Fatalf("cleanup stderr = %q", &stderr)
			}
			assertDockerCalls(t, opt, trace, tc.snapshot, tc.build, tc.productExit == 0, tc.cancel)
			if tc.largeLogs {
				data, err := os.ReadFile(filepath.Join(work, "product-out", "emulator.log"))
				if err != nil || len(data) != 2<<20 || bytes.Count(data, []byte("a")) != 1<<20 ||
					bytes.Count(data, []byte("b")) != 1<<20 {
					t.Fatalf("product log: got %d bytes, error %v", len(data), err)
				}
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

func assertDockerCalls(t *testing.T, opt options, trace string, hasBuild, hasNetwork, hasJudge, canceled bool) {
	t.Helper()
	data, err := os.ReadFile(trace)
	if err != nil {
		t.Fatal(err)
	}
	var got [][]string
	for call := range strings.SplitSeq(strings.TrimSuffix(string(data), "\x00\x00"), "\x00\x00") {
		got = append(got, strings.Split(call, "\x00"))
	}
	uid, gid := os.Getuid(), os.Getgid()
	tree := filepath.Join(opt.work, "tree")
	want := [][]string{generationDockerArgs(opt, tree, filepath.Join(opt.work, "gen-out"), uid, gid)}
	if hasBuild {
		if len(got) < 2 {
			t.Fatalf("missing build command in %q", got)
		}
		i := slices.Index(got[1], "--name")
		if i < 0 || i+1 >= len(got[1]) {
			t.Fatalf("missing build container name in %q", got[1])
		}
		buildName := got[1][i+1]
		name, ok := strings.CutSuffix(buildName, "-build")
		if !ok || !strings.HasPrefix(name, "p0-check-") || name == "p0-check-" {
			t.Fatalf("invalid build container name %q", buildName)
		}
		buildOut := filepath.Join(opt.work, "build-out")
		want = append(want, buildDockerArgs(opt, tree, buildOut, buildName, uid, gid))
		if hasNetwork {
			network, product, judge := name+"-net", name+"-product", name+"-judge"
			want = append(want,
				[]string{"network", "create", "--internal", "--opt", "com.docker.network.bridge.gateway_mode_ipv4=isolated", network},
				productDockerArgs(opt, buildOut, network, product, uid, gid))
			if hasJudge {
				want = append(want, judgeDockerArgs(opt, filepath.Join(opt.work, "judge-out"), network, judge, uid, gid))
			}
			want = append(want, []string{"kill", product}, []string{"logs", product}, []string{"rm", "-f", product})
			if canceled {
				want = append(want, []string{"rm", "-f", judge})
			}
			want = append(want, []string{"network", "rm", network})
		}
	}
	if !slices.EqualFunc(got, want, slices.Equal[[]string]) {
		t.Fatalf("Docker calls\ngot  %q\nwant %q", got, want)
	}
}

func TestReadCheckOutput(t *testing.T) {
	out := t.TempDir()
	target := filepath.Join(t.TempDir(), "valid.json")
	writeTestFile(t, target, "{}", 0o644)
	result := filepath.Join(out, "p0check.json")
	if err := os.Symlink(target, result); err != nil {
		t.Fatal(err)
	}
	if _, err := readCheckOutput(out); err == nil || !strings.Contains(err.Error(), "regular output file") {
		t.Fatalf("expected symlink rejection, got %v", err)
	}
	if err := os.Remove(result); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, result, strings.Repeat(" ", 1<<20+1), 0o644)
	if _, err := readCheckOutput(out); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("expected size limit rejection, got %v", err)
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
	result, code := run(t.Context(), []string{"-product", "test", "-task", "sm-create-get", "-p0check", "test", "-work", "test", "-no-patch"}, io.Discard)
	if code != 2 || result.Error != "invalid arguments" {
		t.Fatalf("missing runner: exit %d, result %+v", code, result)
	}
}
