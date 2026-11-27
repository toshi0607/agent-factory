package patchcheck

import (
	"fmt"
	"slices"
	"strings"
	"testing"
)

func TestInspectReturnsSortedUniquePaths(t *testing.T) {
	dir := t.TempDir()
	git := func(args ...string) string {
		t.Helper()
		out, err := Git(dir, nil, args...)
		if err != nil {
			t.Fatal(err)
		}
		return strings.TrimSpace(string(out))
	}
	git("init", "--template=")
	base := git("write-tree")
	add := func(name string) string {
		return fmt.Sprintf("diff --git a/%[1]s b/%[1]s\nnew file mode 100644\n--- /dev/null\n+++ b/%[1]s\n@@ -0,0 +1 @@\n+new\n", name)
	}
	paths, code, err := Inspect(dir, base, []byte(add("z.go")+add("a.go")+add("z.go")), func(string) bool { return true })
	if code != 0 || err != nil || !slices.Equal(paths, []string{"a.go", "z.go"}) {
		t.Fatalf("Inspect = (%v, %d, %v)", paths, code, err)
	}
}
