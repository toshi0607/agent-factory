package sandbox_test

import (
	"archive/tar"
	"compress/gzip"
	"encoding/base64"
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
	const signURL = "https://signer.example/secret-path?sig=topsecret"
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"aud":"probe-audience","scope":"models:read","exp":2000000000}`))
	token := "fake-header." + payload + ".fake-signature"
	write(t, filepath.Join(home, ".netrc"), fakeSecret)
	write(t, filepath.Join(home, "sample.key"), fakeSecret)
	mkdir(t, filepath.Join(home, ".ssh"))
	write(t, filepath.Join(home, ".ssh", "id_probe"), "PRIVATE KEY\nfile-body-marker\n")
	argv, stdin := filepath.Join(dir, "curl-argv"), filepath.Join(dir, "curl-stdin")
	curl := filepath.Join(bin, "curl")
	if err := os.WriteFile(curl, []byte(`#!/bin/bash
printf '%s\n' "$@" >> "$CURL_ARGV"
url=${!#}
if [[ $url == --version ]]; then
  printf 'curl test version\n'
  exit 0
fi
while (($#)); do
  case $1 in
    --dump-header) dump_header=$2; shift ;;
    --write-out) write_out=$2; shift ;;
    --header)
      if [[ $2 == @- ]]; then
        while IFS= read -r line; do
          printf '%s\n' "${line//"$ANTHROPIC_COMMIT_TOKEN"/[redacted]}"
        done >> "$CURL_STDIN"
        token_request=yes
      fi
      shift
      ;;
  esac
  shift
done
case $url in
  https://proxy.golang.org/|https://sum.golang.org/latest) ;;
  https://api.anthropic.com/*|https://signer.example/*)
    if [[ ${dump_header:-} == - ]]; then
      server=api-test-server
      [[ $url == https://signer.example/* ]] && server=$url
      printf 'HTTP/1.1 200 OK\r\nServer: %s\r\nVia: test-proxy\r\nContent-Type: application/json\r\nRequest-Id: test-request\r\nSet-Cookie: fixture-cookie\r\n\r\n' "$server"
    elif [[ ${token_request:-} != yes ]]; then
      printf 000
      exit 7
    fi
    ;;
  *) printf 000; exit 7 ;;
esac
printf '%b' "${write_out//'%{http_code}'/200}"
`), 0o755); err != nil {
		t.Fatal(err)
	}
	run(t, "", nil, "bash", "-n", "probe.sh")
	env := []string{"PATH=" + bin + ":/usr/bin:/bin", "HOME=" + home, "FACTORY_OUT_DIR=" + out,
		"CURL_ARGV=" + argv, "CURL_STDIN=" + stdin,
		"fAkE_TokEn=" + fakeSecret, "ALLOWED_KEY=also-a-fake-placeholder", "PROBE_ALLOWED_ENV_NAMES=ALLOWED_KEY",
		"ANTHROPIC_COMMIT_TOKEN=" + token, "ANTHROPIC_COMMIT_SIGN_URL=" + signURL}
	for _, allowed := range []bool{false, true} {
		if allowed {
			env = append(env, "PROBE_ALLOWED_ENV_NAMES=ALLOWED_KEY,fAkE_TokEn")
		}
		write(t, argv, "")
		write(t, stdin, "")
		stdout := run(t, "", env, "bash", "probe.sh")
		result := read(t, filepath.Join(out, "probe.txt"))
		if stdout != "" || strings.Contains(result, fakeSecret) || strings.Contains(result, "also-a-fake-placeholder") {
			t.Fatal("probe wrote unexpected output or disclosed a fake credential")
		}
		if strings.Contains(result, token) || strings.Contains(read(t, argv), token) {
			t.Fatal("probe disclosed the platform token in its output or curl arguments")
		}
		if got := read(t, stdin); got != "Authorization: Bearer [redacted]\nx-api-key: [redacted]\n" {
			t.Fatal("probe did not pass the platform token to curl through stdin")
		}
		for _, forbidden := range []string{"secret-path", "topsecret", "file-body-marker", "set-cookie", "fixture-cookie", "test-request"} {
			if strings.Contains(result, forbidden) {
				t.Error("probe disclosed a sign URL component, file contents, or a response header")
			}
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
			"https://api.anthropic.com/ -> 200\nserver api-test-server\n",
			"sign url (GET without the platform token) -> 200\nrequest-id present\n== platform token\n",
			"private_key_marker yes", "scheme https\nhost signer.example\n",
			"claims [\"aud\", \"exp\", \"scope\"]", "aud \"probe-audience\"", "scope \"models:read\"",
			"== summary", "platform_env_present: ANTHROPIC_COMMIT_SIGN_URL ANTHROPIC_COMMIT_TOKEN",
			envSummary, "no_credential_files FAIL", "allowed_hosts_reachable PASS",
			"other_hosts_blocked PASS", "== done\n",
		} {
			if !strings.Contains(result, want) {
				t.Errorf("missing %q in probe result", want)
			}
		}
	}
	for _, tc := range []struct{ name, url string }{
		{"non-https", "http://signer.example/"},
		{"whitespace", "https://signer.example/space here"},
		{"control character", "https://signer.example/\x01"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			write(t, argv, "")
			run(t, "", append(env, "ANTHROPIC_COMMIT_SIGN_URL="+tc.url), "bash", "probe.sh")
			result := read(t, filepath.Join(out, "probe.txt"))
			if !strings.Contains(result, "sign url -> skipped (not https or contains whitespace)\n") ||
				strings.Contains(read(t, argv), "signer.example") {
				t.Fatal("probe did not skip an invalid sign URL")
			}
		})
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

func TestSetupBakedGo(t *testing.T) {
	if _, err := exec.LookPath("sha256sum"); err != nil {
		t.Skip("sha256sum is unavailable")
	}
	for _, tc := range []struct {
		name, version, wantError string
		executable               bool
		corrupt                  string
	}{
		{name: "matching version", version: "go1.26.11", executable: true},
		{name: "different version", version: "go1.26.110", executable: true, wantError: "does not match manifest version go1.26.11"},
		{name: "missing executable", wantError: "must contain an executable bin/go"},
		{name: "corrupt product", version: "go1.26.11", executable: true, corrupt: "product.tar.gz", wantError: "FAILED"},
		{name: "corrupt proxy", version: "go1.26.11", executable: true, corrupt: "modproxy.tar.gz", wantError: "FAILED"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			mounted, work, goRoot := filepath.Join(dir, "delivery"), filepath.Join(dir, "work"), filepath.Join(dir, "baked Go")
			mkdir(t, mounted)
			mkdir(t, goRoot)
			mkdir(t, filepath.Join(goRoot, "bin"))
			write(t, filepath.Join(mounted, "setup.sh"), read(t, "setup.sh"))
			makeArchive(t, filepath.Join(mounted, "product.tar.gz"), map[string]string{"product.go": "package product\n"})
			makeArchive(t, filepath.Join(mounted, "modproxy.tar.gz"), map[string]string{"modproxy/list": "v1.0.0\n"})
			m := delivery.Manifest{Task: "test", BaseCommit: "test-base", Files: []delivery.File{
				{Name: toolchain, SHA256: strings.Repeat("0", 64), Bytes: 42},
			}}
			for _, name := range []string{"product.tar.gz", "modproxy.tar.gz"} {
				entry, err := delivery.Inspect(filepath.Join(mounted, name))
				if err != nil {
					t.Fatal(err)
				}
				m.Files = append(m.Files, entry)
			}
			if err := delivery.WriteAtomic(filepath.Join(mounted, delivery.ManifestName), m.Write); err != nil {
				t.Fatal(err)
			}
			if tc.executable {
				script := "#!/bin/bash\n[[ $1 == version && $GOTOOLCHAIN == local ]] || exit 1\n" +
					"printf 'go version " + tc.version + " linux/amd64\\n'\n"
				if err := os.WriteFile(filepath.Join(goRoot, "bin", "go"), []byte(script), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			if tc.corrupt != "" {
				write(t, filepath.Join(mounted, tc.corrupt), "corrupt archive")
			}
			t.Cleanup(func() {
				if err := os.Chmod(filepath.Join(work, "base"), 0o755); err != nil && !os.IsNotExist(err) {
					t.Error(err)
				}
			})
			env := append(os.Environ(), "FACTORY_WORK_DIR="+work, "FACTORY_GO_ROOT="+goRoot)
			if tc.wantError != "" {
				cmd := exec.CommandContext(t.Context(), "bash", filepath.Join(mounted, "setup.sh"))
				cmd.Env = env
				output, err := cmd.CombinedOutput()
				if err == nil || !strings.Contains(string(output), tc.wantError) {
					t.Fatalf("setup should fail with %q, got %v\n%s", tc.wantError, err, output)
				}
				return
			}
			run(t, "", env, "bash", filepath.Join(mounted, "setup.sh"))
			envFile := filepath.Join(work, "env.sh")
			got := run(t, "", env, "bash", "-c", `source "$1" && command -v go && go version`, "bash", envFile)
			if want := filepath.Join(goRoot, "bin", "go") + "\ngo version go1.26.11 linux/amd64\n"; got != want {
				t.Fatalf("setup did not select baked Go: %q", got)
			}
			if _, err := os.Stat(filepath.Join(work, "toolchain")); !os.IsNotExist(err) {
				t.Fatal("setup used an archive for baked Go")
			}
			if data := read(t, filepath.Join(work, "modproxy", "list")); data != "v1.0.0\n" {
				t.Fatal("setup did not extract the module proxy")
			}
		})
	}
}

func TestCloudflareProbe(t *testing.T) {
	dir := t.TempDir()
	home, bin, out := filepath.Join(dir, "home"), filepath.Join(dir, "bin"), filepath.Join(dir, "out")
	mkdir(t, home)
	mkdir(t, bin)
	curl := `#!/bin/bash
url=${!#}
if [[ $url == --version ]]; then
  printf 'curl test version\n'
  exit 0
fi
method=GET
body=
header=
while (($#)); do
  case $1 in
    --request) method=$2; shift ;;
    --data) body=$2; method=POST; shift ;;
    --header)
      if [[ $2 == @- ]]; then
        IFS= read -r header
      fi
      shift ;;
    --output) [[ $2 == /dev/null ]] || exit 42; shift ;;
    --dump-header) [[ $2 == - ]] || exit 42; shift ;;
  esac
  shift
done
code=403
deny=host_not_allowed
case "$method $url" in
  'GET http://proxy.golang.org/') deny=plain_http ;;
  'GET https://proxy.golang.org:8443/') printf '000\n'; exit 7 ;;
  'GET https://1.1.1.1/') printf '000\n'; exit 35 ;;
  'GET https://proxy.golang.org/'|'GET https://sum.golang.org/latest') code=200; deny= ;;
  'POST https://proxy.golang.org/') deny=method_not_allowed ;;
  'GET https://api.anthropic.com/v1/models')
    deny=llm_path
    [[ $SCENARIO == ordinary-handler-403 ]] && deny=
    ;;
  'POST https://api.anthropic.com/v1/messages')
    [[ $body == *'"model":"wrong-model"'* ]] || exit 42
    deny=llm_model
    ;;
  'POST https://api.anthropic.com/v1/messages/count_tokens')
    [[ $body == *'"model":"claude-test"'* && $body == *'"role":"user"'* && $header == 'x-api-key: provided-by-worker' ]] || exit 42
    code=200
    [[ $SCENARIO == count-201 ]] && code=201
    deny=
    ;;
  'GET https://example.com/')
    if [[ $SCENARIO == ordinary-egress-403 ]]; then
      printf 'HTTP/1.1 200 Connection established\r\nx-factory-denied: host_not_allowed\r\n\r\n'
      deny=
    fi
    ;;
  'GET https://api.anthropic.com/') deny=llm_path ;;
esac
printf 'HTTP/1.1 %s\r\nX-Private-Header: fixture-private-header\r\n' "$code"
[[ -n $deny ]] && printf 'X-Factory-Denied: %s\r\n' "$deny"
printf '\r\n%s\n' "$code"
`
	if err := os.WriteFile(filepath.Join(bin, "curl"), []byte(curl), 0o755); err != nil {
		t.Fatal(err)
	}
	const invalidKey = "synthetic-key-value-do-not-print"
	for _, tc := range []struct {
		scenario, key, keyVerdict, envVerdict, egress, blockedVerdict, count, handlerVerdict string
	}{
		{"pass", "provided-by-worker", "placeholder", "PASS", "403 denied host_not_allowed", "PASS", "200", "PASS"},
		{"bad-key", invalidKey, "invalid", "FAIL", "403 denied host_not_allowed", "PASS", "000", "FAIL"},
		{"ordinary-egress-403", "provided-by-worker", "placeholder", "PASS", "403", "FAIL", "200", "PASS"},
		{"ordinary-handler-403", "provided-by-worker", "placeholder", "PASS", "403 denied host_not_allowed", "PASS", "200", "FAIL"},
		{"count-201", "provided-by-worker", "placeholder", "PASS", "403 denied host_not_allowed", "PASS", "201", "FAIL"},
	} {
		t.Run(tc.scenario, func(t *testing.T) {
			env := []string{"PATH=" + bin + ":/usr/bin:/bin", "HOME=" + home, "FACTORY_OUT_DIR=" + out,
				"FACTORY_CANDIDATE=cloudflare-sandbox", "SCENARIO=" + tc.scenario,
				"ANTHROPIC_API_KEY=" + tc.key, "ANTHROPIC_MODEL=claude-test", "ANTHROPIC_SMALL_FAST_MODEL=claude-fast",
				"ANTHROPIC_DEFAULT_HAIKU_MODEL=claude-test", "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1",
				"CLOUDFLARE_TEST=fixture-private-env", "PROBE_ALLOWED_ENV_NAMES=ANTHROPIC_API_KEY"}
			if stdout := run(t, "", env, "bash", "probe.sh"); stdout != "" {
				t.Fatal("probe wrote to stdout")
			}
			result := read(t, filepath.Join(out, "probe.txt"))
			for _, forbidden := range []string{invalidKey, "fixture-private-env", "fixture-private-header", "provided-by-worker", "claude-fast"} {
				if strings.Contains(result, forbidden) {
					t.Fatal("probe disclosed an environment value or response header")
				}
			}
			for _, want := range []string{
				"ANTHROPIC_API_KEY -> " + tc.keyVerdict + "\n",
				"ANTHROPIC_MODEL\n", "ANTHROPIC_SMALL_FAST_MODEL\n", "ANTHROPIC_DEFAULT_HAIKU_MODEL\n",
				"CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC\n", "CLOUDFLARE_TEST\n",
				"https://example.com/ -> " + tc.egress + "\n",
				"== handler checks\nhttp://proxy.golang.org/ -> 403 denied plain_http\n",
				"https://proxy.golang.org:8443/ -> curl error 7\n",
				"https://1.1.1.1/ -> curl error 35\n",
				"POST https://proxy.golang.org/ -> 403 denied method_not_allowed\n",
				"POST https://api.anthropic.com/v1/messages (wrong model) -> 403 denied llm_model\n",
				"POST https://api.anthropic.com/v1/messages/count_tokens -> " + tc.count + "\n",
				"== platform token\nskipped\n== platform token against the api\nskipped\n",
				"no_credential_env " + tc.envVerdict + "\n", "allowed_hosts_reachable PASS\n",
				"other_hosts_blocked " + tc.blockedVerdict + "\n", "handler_checks " + tc.handlerVerdict + "\n",
			} {
				if !strings.Contains(result, want) {
					t.Errorf("missing %q in Cloudflare probe", want)
				}
			}
		})
	}
}
