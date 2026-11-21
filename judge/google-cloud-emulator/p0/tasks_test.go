package p0

import (
	"slices"
	"testing"
)

func TestTasks(t *testing.T) {
	want := map[string]string{
		"sm-create-get":  "services/secretmanager/",
		"sm-list-delete": "services/secretmanager/",
		"sm-versions":    "services/secretmanager/",
		"tasks-queues":   "services/cloudtasks/",
		"pubsub-topics":  "services/pubsub/",
	}
	tasks := Tasks()
	if len(tasks) != len(want) {
		t.Fatalf("got %d tasks, want %d", len(tasks), len(want))
	}
	for _, task := range tasks {
		dir, ok := want[task.ID]
		if !ok {
			t.Errorf("unexpected or duplicate task ID %q", task.ID)
			continue
		}
		delete(want, task.ID)
		t.Run(task.ID, func(t *testing.T) {
			found, ok := Lookup(task.ID)
			if !ok || found.ID != task.ID || found.Check == nil || task.Check == nil {
				t.Fatalf("expected registered check for %q, got %+v, %t", task.ID, found, ok)
			}
			if !slices.Equal(task.WritablePaths, []string{dir + "*.go"}) ||
				!slices.Equal(task.ExcludedPaths, []string{dir + "*.gen.go"}) {
				t.Fatalf("unexpected path patterns: %+v", task)
			}
			other := "services/pubsub/"
			if dir == other {
				other = "services/secretmanager/"
			}
			for _, tc := range []struct {
				path string
				want bool
			}{
				{dir + "state.go", true},
				{dir + "new file.go", true},
				{dir + "register.gen.go", false},
				{dir + "subdir/state.go", false},
				{dir + "state.txt", false},
				{other + "state.go", false},
				{"/" + dir + "state.go", false},
			} {
				if got := PathAllowed(task, tc.path); got != tc.want {
					t.Errorf("PathAllowed(%q) = %t, want %t", tc.path, got, tc.want)
				}
			}
		})
	}
}

func TestLookupUnknown(t *testing.T) {
	if _, ok := Lookup("unknown"); ok {
		t.Fatal("unknown task was found")
	}
}
