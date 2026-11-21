package sandbox_test

import (
	"archive/tar"
	"compress/gzip"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/toshi0607/agent-factory/internal/delivery"
)

const toolchain = "go1.26.11.linux-amd64.tar.gz"

func TestSandboxScripts(t *testing.T) {
	if _, err := exec.LookPath("sha256sum"); err != nil {
		t.Skip("sha256sum is unavailable")
	}
	for _, script := range []string{"setup.sh", "finish.sh"} {
		run(t, "", nil, "bash", "-n", script)
	}
	for _, name := range []string{"with git", "without git or python", "agent committed", "agent deleted git",
		"ignored build output", "nested repo without commits", "nested repo with a commit", "nested repo with git failure"} {
		t.Run(name, func(t *testing.T) {
			testSandbox(t, name)
		})
	}
}

func TestProbe(t *testing.T) {
	dir := t.TempDir()
	home, bin, out := filepath.Join(dir, "home"), filepath.Join(dir, "bin"), filepath.Join(dir, "out")
	mkdir(t, home)
	mkdir(t, bin)
	const fakeSecret = "fake-secret-value-never-print"
	write(t, filepath.Join(home, ".netrc"), fakeSecret)
	write(t, filepath.Join(home, "sample.key"), fakeSecret)
	curl := filepath.Join(bin, "curl")
	if err := os.WriteFile(curl, []byte(`#!/bin/bash
case ${!#} in
  --version) printf 'curl test version\n' ;;
  https://proxy.golang.org/|https://sum.golang.org/latest) printf 200 ;;
  *) printf 000; exit 7 ;;
esac
`), 0o755); err != nil {
		t.Fatal(err)
	}
	run(t, "", nil, "bash", "-n", "probe.sh")
	env := []string{"PATH=" + bin + ":/usr/bin:/bin", "HOME=" + home, "FACTORY_OUT_DIR=" + out,
		"fAkE_TokEn=" + fakeSecret, "ALLOWED_KEY=also-a-fake-placeholder", "PROBE_ALLOWED_ENV_NAMES=ALLOWED_KEY",
		"ANTHROPIC_COMMIT_TOKEN=" + fakeSecret, "ANTHROPIC_COMMIT_SIGN_URL=" + fakeSecret}
	for _, allowed := range []bool{false, true} {
		if allowed {
			env = append(env, "PROBE_ALLOWED_ENV_NAMES=ALLOWED_KEY,fAkE_TokEn")
		}
		stdout := run(t, "", env, "bash", "probe.sh")
		result := read(t, filepath.Join(out, "probe.txt"))
		if stdout != "" || strings.Contains(result, fakeSecret) || strings.Contains(result, "also-a-fake-placeholder") {
			t.Fatal("probe wrote unexpected output or disclosed a fake credential")
		}
		envSummary := "no_credential_env FAIL"
		if allowed {
			envSummary = "no_credential_env PASS"
		}
		for _, want := range []string{
			"== tools", "curl -> found", "curl test version",
			"== credential-like environment variable names", "fAkE_TokEn", "ALLOWED_KEY",
			"== credential-like files", "~/.netrc -> yes", "sample.key -> yes", "~/.aws -> no",
			"== egress", "https://proxy.golang.org/ -> 200", "https://sum.golang.org/latest -> 200",
			"https://example.com/ -> curl error 7", "https://registry.npmjs.org/ -> curl error 7",
			"== summary", "platform_env_present: ANTHROPIC_COMMIT_SIGN_URL ANTHROPIC_COMMIT_TOKEN",
			envSummary, "no_credential_files FAIL", "allowed_hosts_reachable PASS",
			"other_hosts_blocked PASS", "== done\n",
		} {
			if !strings.Contains(result, want) {
				t.Errorf("missing %q in probe result", want)
			}
		}
	}
}

func testSandbox(t *testing.T, scenario string) {
	useGit := scenario != "without git or python"
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	mounted := filepath.Join(dir, "delivery")
	work := filepath.Join(dir, "work with spaces")
	out := filepath.Join(dir, "outputs")
	mkdir(t, mounted)
	for _, script := range []string{"setup.sh", "finish.sh"} {
		write(t, filepath.Join(mounted, script), read(t, script))
	}
	write(t, filepath.Join(mounted, "task.md"), "Fix one task.\n")
	archive := filepath.Join(mounted, "product.tar.gz")
	makeArchive(t, archive, map[string]string{
		".gitignore": "build.out\n",
		"edit.go":    "package product\n\nconst original = true\n",
		"delete.go":  "package product\n\nconst toDelete = true\n",
		"keep.go":    "package product\n",
	})
	makeArchive(t, filepath.Join(mounted, toolchain), map[string]string{"go/bin/go": "fake toolchain\n"})
	names := []string{"setup.sh", "finish.sh", "task.md", "product.tar.gz", toolchain}
	if useGit {
		makeArchive(t, filepath.Join(mounted, "modproxy.tar.gz"), map[string]string{
			"modproxy/example.invalid/module/@v/list": "v1.0.0\n",
		})
		names = append(names, "modproxy.tar.gz")
	}
	m := delivery.Manifest{Task: "test", BaseCommit: "fake_base"}
	for _, name := range names {
		entry, err := delivery.Inspect(filepath.Join(mounted, name))
		if err != nil {
			t.Fatal(err)
		}
		m.Files = append(m.Files, entry)
	}
	if err := delivery.WriteAtomic(filepath.Join(mounted, delivery.ManifestName), m.Write); err != nil {
		t.Fatal(err)
	}

	bin := filepath.Join(dir, "bin")
	mkdir(t, bin)
	commands := []string{"dirname", "mkdir", "sha256sum", "tar", "chmod", "mktemp", "rm", "sort", "ln", "find", "cmp", "mv", "cat", "wc", "grep", "sed", "awk"}
	if useGit {
		commands = append(commands, "git", "python3")
	}
	for _, name := range commands {
		linkTool(t, bin, name, name)
	}
	diff := "diff"
	if _, err := exec.LookPath("gdiff"); err == nil {
		diff = "gdiff"
	}
	linkTool(t, bin, "diff", diff)

	env := append(os.Environ(), "PATH="+bin, "FACTORY_WORK_DIR="+work, "FACTORY_OUT_DIR="+out)
	t.Cleanup(func() {
		// The setup script removes write permission from the base directories.
		err := filepath.WalkDir(filepath.Join(work, "base"), func(path string, entry fs.DirEntry, err error) error {
			if err == nil && entry.IsDir() {
				return os.Chmod(path, 0o755)
			}
			return err
		})
		if err != nil && !os.IsNotExist(err) {
			t.Error(err)
		}
	})
	setup := run(t, "", env, "bash", filepath.Join(mounted, "setup.sh"))
	if !strings.Contains(setup, "Product: "+filepath.Join(work, "product")) ||
		!strings.Contains(setup, "Task: "+filepath.Join(mounted, "task.md")) {
		t.Fatalf("setup output = %q", setup)
	}
	var source string
	for line := range strings.SplitSeq(setup, "\n") {
		if strings.HasPrefix(line, "source ") {
			source = line
		}
	}
	if source == "" {
		t.Fatalf("setup did not print a source command: %q", setup)
	}
	printEnv := source + ` && printf '%s\n' "$PATH" "$GOTOOLCHAIN" "$GOCACHE" "$GOMODCACHE" "$GOSUMDB" "$GOPROXY"`
	proxy := "https://proxy.golang.org"
	if useGit {
		proxy = "file://" + filepath.Join(work, "modproxy") + "," + proxy
		if got := read(t, filepath.Join(work, "modproxy/example.invalid/module/@v/list")); got != "v1.0.0\n" {
			t.Fatalf("module proxy contents = %q", got)
		}
	}
	gotEnv := run(t, "", env, "bash", "-c", printEnv)
	wantEnv := []string{filepath.Join(work, "toolchain/go/bin") + ":" + bin, "local", filepath.Join(work, "gocache"),
		filepath.Join(work, "gomodcache"), "sum.golang.org", proxy}
	if !slices.Equal(strings.Split(strings.TrimSuffix(gotEnv, "\n"), "\n"), wantEnv) {
		t.Fatalf("env.sh exports %q, want %q", gotEnv, wantEnv)
	}
	baseFile := filepath.Join(work, "base", "edit.go")
	baseInfo, err := os.Stat(baseFile)
	if err != nil {
		t.Fatal(err)
	}
	if baseInfo.Mode().Perm()&0o222 != 0 {
		t.Fatal("base file is writable")
	}

	product := filepath.Join(work, "product")
	write(t, filepath.Join(product, "edit.go"), "package product\n\nconst updated = true\n")
	write(t, filepath.Join(product, "added.go"), "package product\n\nconst added = true\n")
	if err := os.Remove(filepath.Join(product, "delete.go")); err != nil {
		t.Fatal(err)
	}
	wantPaths := "added.go\ndelete.go\nedit.go\n"
	switch scenario {
	case "agent committed":
		run(t, product, nil, "git", "add", "-A")
		run(t, product, nil, "git", "-c", "core.hooksPath=/dev/null", "-c", "user.name=Test",
			"-c", "user.email=test@example.invalid", "commit", "--no-gpg-sign", "-m", "Agent changes")
	case "agent deleted git":
		if err := os.RemoveAll(filepath.Join(product, ".git")); err != nil {
			t.Fatal(err)
		}
	case "ignored build output":
		write(t, filepath.Join(product, "build.out"), "local build output\n")
	case "nested repo without commits", "nested repo with a commit", "nested repo with git failure":
		nested := filepath.Join(product, "nested")
		mkdir(t, nested)
		run(t, nested, nil, "git", "init", "--quiet", "--template=")
		write(t, filepath.Join(nested, "ordinary.txt"), "nested file\n")
		if scenario == "nested repo with a commit" {
			run(t, nested, nil, "git", "add", "ordinary.txt")
			run(t, nested, nil, "git", "-c", "core.hooksPath=/dev/null", "-c", "user.name=Test",
				"-c", "user.email=test@example.invalid", "commit", "--no-gpg-sign", "-m", "Nested changes")
		}
		wantPaths += "nested/ordinary.txt\n"
	}
	if scenario == "nested repo with git failure" {
		git := filepath.Join(bin, "git")
		if err := os.Remove(git); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(git, []byte("#!/bin/bash\nexit 1\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	finish := filepath.Join(mounted, "finish.sh")
	for range 2 {
		message := run(t, "", env, "bash", finish)
		if !strings.HasPrefix(message, wantPaths) || !strings.Contains(message, "Patch bytes: ") {
			t.Fatalf("finish output = %q", message)
		}
		if got := read(t, filepath.Join(out, "changed-paths.txt")); got != wantPaths {
			t.Fatalf("changed paths = %q", got)
		}
	}

	fresh := filepath.Join(dir, "fresh")
	mkdir(t, fresh)
	run(t, "", nil, "tar", "-xzf", archive, "-C", fresh)
	patch := filepath.Join(out, "patch.diff")
	if strings.HasPrefix(scenario, "nested repo") {
		stats := run(t, fresh, nil, "git", "apply", "--numstat", "-z", "-p1", patch)
		for stat := range strings.SplitSeq(strings.TrimSuffix(stats, "\x00"), "\x00") {
			fields := strings.SplitN(stat, "\t", 3)
			if len(fields) != 3 {
				t.Fatalf("unexpected patch stat: %q", stat)
			}
			path := fields[2]
			if slices.Contains(strings.Split(path, "/"), ".git") {
				t.Fatalf("patch includes Git metadata: %s", path)
			}
		}
	}
	run(t, fresh, nil, "git", "apply", "-p1", patch)
	got, want := tree(t, fresh), tree(t, product)
	if scenario == "ignored build output" {
		delete(want, "build.out")
	}
	if len(got) != len(want) {
		t.Fatalf("patched tree = %v, want %v", got, want)
	}
	for path, content := range want {
		if actual, ok := got[path]; !ok || content != actual {
			t.Fatalf("patched file %s = %q, want %q", path, actual, content)
		}
	}
}

func linkTool(t *testing.T, dir, name, tool string) {
	t.Helper()
	path, err := exec.LookPath(tool)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(path, filepath.Join(dir, name)); err != nil {
		t.Fatal(err)
	}
}

func makeArchive(t *testing.T, path string, files map[string]string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	for name, content := range files {
		h := tar.Header{Name: name, Mode: 0o644, Size: int64(len(content)), ModTime: time.Unix(1700000000, 0)}
		if err := tw.WriteHeader(&h); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	for _, close := range []func() error{tw.Close, gz.Close, f.Close} {
		if err := close(); err != nil {
			t.Fatal(err)
		}
	}
}

func tree(t *testing.T, root string) map[string]string {
	t.Helper()
	files := make(map[string]string)
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if entry.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		files[rel] = read(t, path)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return files
}

func mkdir(t *testing.T, name string) {
	t.Helper()
	if err := os.Mkdir(name, 0o755); err != nil {
		t.Fatal(err)
	}
}

func write(t *testing.T, name, content string) {
	t.Helper()
	if err := os.WriteFile(name, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func read(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func run(t *testing.T, dir string, env []string, name string, args ...string) string {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), name, args...)
	cmd.Env, cmd.Dir = env, dir
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v: %v\n%s", name, args, err, output)
	}
	return string(output)
}
