package policy

import (
	"io"
	"os"
	"slices"
	"strings"
	"testing"
)

func decode(r io.Reader) (Policy, error) { return Decode(r) }

func TestReflectPathPatterns(t *testing.T) {
	for _, tc := range []struct {
		pattern, path string
		want          bool
	}{
		{"services/*/*.go", "services/secretmanager/state.go", true},
		{"services/*/*.go", "services/secretmanager/nested/state.go", false},
		{"services/*/*.go", "services//state.go", false},
		{"services/*/*.go", "services/SecretManager/state.go", true},
		{"services/*/*.go", "Services/secretmanager/state.go", false},
		{"services/*/*.go", "services/secretmanager/state.GO", false},
		{"foo*bar*baz", "fooxbarbarbaz", true},
		{"foo*bar*bar", "foobar", false},
		{"pre**post", "prexpost", true},
		{"pre**post", "pre/x/post", false},
		{"**/*.gen.go", "root.gen.go", true},
		{"**/*.gen.go", "a/b/file.gen.go", true},
		{"a/**/b", "a/b", true},
		{"a/**/b", "a/c/d/b", true},
		{"a/**/b", "a/b/c", false},
		{"a/**", "a", true},
		{"a/**", "a/b/c", true},
		{"a/**", "ab/c", false},
		{"**", "/a", false},
		{"**", "a/", false},
		{"café/**", "cafe\u0301/path", false},
	} {
		t.Run(tc.pattern+"="+tc.path, func(t *testing.T) {
			if got := MatchPath(tc.pattern, tc.path); got != tc.want {
				t.Fatalf("MatchPath(%q, %q) = %t, want %t", tc.pattern, tc.path, got, tc.want)
			}
		})
	}
}

func TestReflectPolicyValidation(t *testing.T) {
	data, err := os.ReadFile("../../policy/google-cloud-emulator.yaml")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, field, value, reason string }{
		{"empty pattern", "write: [services/*/*.go]", "write: ['']", "write"},
		{"absolute pattern", "write: [services/*/*.go]", "write: [/services/**]", "write"},
		{"dot segment", "write: [services/*/*.go]", "write: [services/./*.go]", "write"},
		{"dot-dot segment", "write: [services/*/*.go]", "write: [services/../*.go]", "write"},
		{"trailing slash", "write: [services/*/*.go]", "write: [services/]", "write"},
		{"double slash", "write: [services/*/*.go]", "write: [services//*.go]", "write"},
		{"question mark", "write: [services/*/*.go]", "write: ['services/?.go']", "write"},
		{"brackets", "write: [services/*/*.go]", "write: ['services/[ab].go']", "write"},
		{"braces", "write: [services/*/*.go]", "write: ['services/{a,b}.go']", "write"},
		{"backslash", "write: [services/*/*.go]", "write: ['services\\*.go']", "write"},
		{"too many patterns", "write: [services/*/*.go]", "write: [" + strings.Join(slices.Repeat([]string{"foo"}, 65), ", ") + "]", "at most 64"},
		{"bad generated", "docs/coverage/**", "docs/?", "reflect.generated"},
		{"bad dependency", "dependency_files: [go.mod, go.sum]", "dependency_files: ['[']", "reflect.dependency_files"},
		{"bad protected", "- Makefile", "- /Makefile", "reflect.protected"},
		{"missing target", "target_refs: [refs/heads/factory-f0]", "target_refs: []", "reflect.target_refs is required"},
		{"target pattern", "target_refs: [refs/heads/factory-f0]", "target_refs: ['refs/heads/*']", "invalid exact ref"},
		{"target shorthand", "target_refs: [refs/heads/factory-f0]", "target_refs: [factory-f0]", "invalid exact ref"},
		{"target traversal", "target_refs: [refs/heads/factory-f0]", "target_refs: [refs/heads/../factory-f0]", "invalid exact ref"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Decode(strings.NewReader(strings.Replace(string(data), tc.field, tc.value, 1)))
			if err == nil || !strings.Contains(err.Error(), tc.reason) {
				t.Fatalf("Decode error = %v, want %q", err, tc.reason)
			}
		})
	}
	withoutWrite := strings.Replace(string(data), "    write: [services/*/*.go]\n", "", 1)
	withoutReflect := strings.Split(withoutWrite, "\nreflect:\n")[0]
	if _, err := Decode(strings.NewReader(withoutReflect)); err != nil {
		t.Fatalf("legacy policy without reflect or write: %v", err)
	}
}

func TestReflectPolicyPermissions(t *testing.T) {
	p, err := Load("../../policy/google-cloud-emulator.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if p.RoleMayWrite("probe", "services/pubsub/state.go") || p.RoleMayWrite("fixer-pinned", "services/pubsub/state.go") ||
		!p.RoleMayWrite("fixer", "services/pubsub/state.go") || !p.TargetRefAllowed("refs/heads/factory-f0") ||
		p.TargetRefAllowed("refs/heads/factory-f0/extra") || !p.Protected("Makefile") {
		t.Fatal("unexpected checked-in permissions")
	}

	p.Reflect.Protected = nil
	p.Roles["fixer"] = Role{Write: []string{"**"}}
	for _, path := range []string{
		".github/workflows/test.yml", "AGENTS.md", "a/b/AGENTS.md", "CLAUDE.md", "a/CLAUDE.md",
		".claude/settings.json", "a/.claude/settings.json", ".codex/config.toml", "a/.codex/config.toml",
		".git/config", ".gitmodules", ".gitattributes", "a/.gitattributes",
	} {
		if !p.Protected(path) || p.RoleMayWrite("fixer", path) {
			t.Errorf("built-in protection missing for %q", path)
		}
	}
	for _, path := range []string{"file.gen.go", "docs/coverage/report.md", "snapshot.json", "a/unimplemented.json"} {
		if !p.Generated(path) || p.RoleMayWrite("fixer", path) {
			t.Errorf("generated path writable by role: %q", path)
		}
	}
	for _, path := range []string{"go.mod", "go.sum"} {
		if !p.DependencyFile(path) || p.RoleMayWrite("fixer", path) {
			t.Errorf("dependency file writable by role: %q", path)
		}
	}
	if p.DependencyFile("a/go.mod") || p.Protected("CLAUDE.md.backup") || !p.RoleMayWrite("fixer", "claude.md") {
		t.Fatal("path patterns did not respect case or segment boundaries")
	}
}
