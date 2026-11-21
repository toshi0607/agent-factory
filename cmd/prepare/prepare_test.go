package main

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/toshi0607/agent-factory/internal/delivery"
	"github.com/toshi0607/agent-factory/internal/policy"
)

type transportFunc func(*http.Request) (*http.Response, error)

func (f transportFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func response(code int, body string) *http.Response {
	return &http.Response{StatusCode: code, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}
}

func TestToolchainVerification(t *testing.T) {
	const name = "go1.26.11.linux-amd64.tar.gz"
	const content = "verified toolchain archive"
	digest := fmt.Sprintf("%x", sha256.Sum256([]byte(content)))
	for _, tt := range []struct {
		name, existing, body, wantError string
		size                            int64
		downloads                       int
	}{
		{"cached", content, "", "", int64(len(content)), 0},
		{"download", "stale data", content, "", int64(len(content)), 1},
		{"bad hash", "stale data", "corrupt", "sha256 mismatch", int64(len(content)), 1},
		{"bad size", "", content, "size mismatch", 999, 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			out := t.TempDir()
			path := filepath.Join(out, name)
			if tt.existing != "" {
				mustWrite(t, path, tt.existing)
			}
			var downloads int
			p := preparer{http: &http.Client{Transport: transportFunc(func(r *http.Request) (*http.Response, error) {
				downloads++
				if r.Method != "GET" || r.URL.String() != "https://go.example.invalid/tool" {
					t.Fatalf("unexpected request %s %s", r.Method, r.URL)
				}
				return response(200, tt.body), nil
			})}}
			err := p.prepareToolchain(t.Context(), out, policy.Go{
				Filename: name, URL: "https://go.example.invalid/tool", SHA256: digest, SizeBytes: tt.size,
			})
			if downloads != tt.downloads {
				t.Fatalf("%d downloads, want %d", downloads, tt.downloads)
			}
			if tt.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantError) {
					t.Fatalf("error = %v, want %s", err, tt.wantError)
				}
				if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("invalid toolchain still present: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := mustRead(t, path); got != content {
				t.Fatalf("toolchain = %q", got)
			}
		})
	}
}

func TestPrepare(t *testing.T) {
	product, head := gitProduct(t)
	t.Chdir("../..")
	out := t.TempDir()
	const archive = "fake toolchain"
	const toolchainName = "go1.26.11.linux-amd64.tar.gz"
	policyPath := filepath.Join(t.TempDir(), "policy.yaml")
	body := mustRead(t, "policy/google-cloud-emulator.yaml")
	body = strings.Replace(body, "https://go.dev/dl/"+toolchainName, "https://go.example.invalid/tool", 1)
	body = strings.Replace(body, "9849f4e04ee35303714e34fbc3ac8ab44ea3e448a95aa182f91e3b9b79c710ec",
		fmt.Sprintf("%x", sha256.Sum256([]byte(archive))), 1)
	body = strings.Replace(body, "66999944", fmt.Sprint(len(archive)), 1)
	mustWrite(t, policyPath, body)

	var requests []string
	p := preparer{
		proxyBase: "https://proxy.example.invalid/testing/",
		goList: func(_ context.Context, dir string) (string, error) {
			if dir != product {
				t.Fatalf("go list directory = %q, want %q", dir, product)
			}
			return "\nexample.invalid/Direct v1.0.0\nexample.invalid/Cloud v1.2.3\n" +
				"github.com/toshi0607/google-cloud-emulator v1.0.0\n" +
				"example.invalid/NoVersion \nexample.invalid/Cloud v1.2.3\n", nil
		},
		http: &http.Client{Transport: transportFunc(func(r *http.Request) (*http.Response, error) {
			requests = append(requests, r.Method+" "+r.URL.Host+r.URL.Path)
			if r.URL.Host == "go.example.invalid" && r.Method == "GET" && r.URL.Path == "/tool" {
				return response(200, archive), nil
			}
			if r.URL.Host == "storage.example.invalid" && r.Method == "GET" && r.URL.Path == "/cloud.zip" {
				return response(200, "zip"), nil
			}
			if r.URL.Host != "proxy.example.invalid" {
				t.Fatalf("unexpected request host %s", r.URL.Host)
			}
			switch r.Method + " " + r.URL.Path {
			case "HEAD /testing/example.invalid/!direct/@v/v1.0.0.zip":
				return response(200, ""), nil
			case "HEAD /testing/example.invalid/!cloud/@v/v1.2.3.zip", "GET /testing/example.invalid/!cloud/@v/v1.2.3.zip":
				resp := response(302, "")
				resp.Header.Set("Location", "https://storage.example.invalid/cloud.zip")
				return resp, nil
			case "GET /testing/example.invalid/!cloud/@v/v1.2.3.info":
				return response(200, "info"), nil
			case "GET /testing/example.invalid/!cloud/@v/v1.2.3.mod":
				return response(200, "mod"), nil
			default:
				t.Fatalf("unexpected request %s %s", r.Method, r.URL)
				return nil, nil
			}
		})},
	}
	args := []string{"-policy", policyPath, "-product", product, "-task", "sm-create-get", "-out", out}
	if err := p.run(t.Context(), args); err != nil {
		t.Fatal(err)
	}
	wantRequests := []string{
		"GET go.example.invalid/tool",
		"HEAD proxy.example.invalid/testing/example.invalid/!cloud/@v/v1.2.3.zip",
		"GET proxy.example.invalid/testing/example.invalid/!cloud/@v/v1.2.3.info",
		"GET proxy.example.invalid/testing/example.invalid/!cloud/@v/v1.2.3.mod",
		"GET proxy.example.invalid/testing/example.invalid/!cloud/@v/v1.2.3.zip",
		"GET storage.example.invalid/cloud.zip",
		"HEAD proxy.example.invalid/testing/example.invalid/!direct/@v/v1.0.0.zip",
	}
	if !slices.Equal(requests, wantRequests) {
		t.Fatalf("requests = %q, want %q", requests, wantRequests)
	}

	raw := mustRead(t, filepath.Join(out, delivery.ManifestName))
	var manifest delivery.Manifest
	if err := json.Unmarshal([]byte(raw), &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.Task != "sm-create-get" || manifest.BaseCommit != head {
		t.Fatalf("unexpected manifest metadata: %+v", manifest)
	}
	names := []string{"setup.sh", "finish.sh", "probe.sh", "task.md", "product.tar.gz", toolchainName, "modproxy.tar.gz"}
	lines := strings.Split(strings.TrimSuffix(raw, "\n"), "\n")
	if len(lines) != len(names)+2 || len(manifest.Files) != len(names) {
		t.Fatalf("one object per line required, got %s", raw)
	}
	for i, name := range names {
		file := manifest.Files[i]
		actual, err := delivery.Inspect(filepath.Join(out, name))
		if err != nil {
			t.Fatal(err)
		}
		if file != actual {
			t.Fatalf("manifest entry = %+v, want %+v", file, actual)
		}
		var line delivery.File
		if err := json.Unmarshal([]byte(strings.TrimSuffix(lines[i+1], ",")), &line); err != nil || line != file {
			t.Fatalf("invalid file object on its own line: %q", lines[i+1])
		}
	}
	if got := mustRead(t, filepath.Join(out, "task.md")); got != mustRead(t, "poc/tasks/sm-create-get.md") {
		t.Fatal("task text was not copied")
	}
	if got := mustRead(t, filepath.Join(out, "probe.sh")); got != mustRead(t, "sandbox/probe.sh") {
		t.Fatal("probe script was not copied")
	}
	assertArchive(t, filepath.Join(out, "product.tar.gz"), map[string]string{"main.go": "package product\n"})
	entries := map[string]string{
		"modproxy/example.invalid/!cloud/@v/list":        "v1.2.3\n",
		"modproxy/example.invalid/!cloud/@v/v1.2.3.info": "info",
		"modproxy/example.invalid/!cloud/@v/v1.2.3.mod":  "mod",
		"modproxy/example.invalid/!cloud/@v/v1.2.3.zip":  "zip",
	}
	assertArchive(t, filepath.Join(out, "modproxy.tar.gz"), entries)
	for name, content := range entries {
		if got := mustRead(t, filepath.Join(out, name)); got != content {
			t.Fatalf("%s = %q, want %q", name, got, content)
		}
	}

	hasProxy, err := p.prepareModules(t.Context(), out, "example.invalid/Direct v1.0.0\n", "unused")
	if err != nil || hasProxy {
		t.Fatalf("direct-only modules: archive = %t, err = %v", hasProxy, err)
	}
	if _, err := os.Stat(filepath.Join(out, "modproxy.tar.gz")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("direct-only modules left an archive: %v", err)
	}
}

func TestDirtyProductRejected(t *testing.T) {
	product, _ := gitProduct(t)
	mustWrite(t, filepath.Join(product, "untracked.go"), "package product\n")
	out := filepath.Join(t.TempDir(), "delivery")
	p := preparer{}
	err := p.run(t.Context(), []string{
		"-policy", "../../policy/google-cloud-emulator.yaml", "-product", product,
		"-task", "sm-create-get", "-out", out,
	})
	if err == nil || !strings.Contains(err.Error(), "product tree is dirty") {
		t.Fatalf("expected dirty product failure, got %v", err)
	}
	if _, err := os.Stat(out); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("prepare wrote output for dirty product: %v", err)
	}
}

func gitProduct(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	git := func(args ...string) string {
		t.Helper()
		cmd := exec.CommandContext(t.Context(), "git", append([]string{"-C", dir}, args...)...)
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, output)
		}
		return strings.TrimSpace(string(output))
	}
	git("init", "--quiet")
	mustWrite(t, filepath.Join(dir, "main.go"), "package product\n")
	git("add", "main.go")
	git("-c", "core.hooksPath=/dev/null", "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
		"commit", "--quiet", "--no-gpg-sign", "-m", "test fixture")
	return dir, git("rev-parse", "HEAD")
}

func assertArchive(t *testing.T, path string, want map[string]string) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	defer gz.Close()
	archive := tar.NewReader(gz)
	for {
		entry, err := archive.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if entry.Typeflag != tar.TypeReg {
			continue
		}
		data, err := io.ReadAll(archive)
		if err != nil {
			t.Fatal(err)
		}
		if expected, ok := want[entry.Name]; !ok || string(data) != expected {
			t.Fatalf("unexpected archive file %s: %q", entry.Name, data)
		}
		delete(want, entry.Name)
	}
	if len(want) != 0 {
		t.Fatalf("files missing from archive: %v", want)
	}
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func mustRead(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}
