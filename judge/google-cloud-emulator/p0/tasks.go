package p0

import (
	"context"
	"path"
	"slices"

	"google.golang.org/grpc"
)

type Failure struct{ Name, Message string }

type Task struct {
	ID            string
	WritablePaths []string
	ExcludedPaths []string
	Check         func(ctx context.Context, conn grpc.ClientConnInterface) []Failure
}

func Tasks() []Task {
	return []Task{
		{
			ID:            "sm-create-get",
			WritablePaths: []string{"services/secretmanager/*.go"},
			ExcludedPaths: []string{"services/secretmanager/*.gen.go"},
			Check:         checkSMCreateGet,
		},
		{
			ID:            "sm-list-delete",
			WritablePaths: []string{"services/secretmanager/*.go"},
			ExcludedPaths: []string{"services/secretmanager/*.gen.go"},
			Check:         checkSMListDelete,
		},
		{
			ID:            "sm-versions",
			WritablePaths: []string{"services/secretmanager/*.go"},
			ExcludedPaths: []string{"services/secretmanager/*.gen.go"},
			Check:         checkSMVersions,
		},
		{
			ID:            "tasks-queues",
			WritablePaths: []string{"services/cloudtasks/*.go"},
			ExcludedPaths: []string{"services/cloudtasks/*.gen.go"},
			Check:         checkTasksQueues,
		},
		{
			ID:            "pubsub-topics",
			WritablePaths: []string{"services/pubsub/*.go"},
			ExcludedPaths: []string{"services/pubsub/*.gen.go"},
			Check:         checkPubSubTopics,
		},
	}
}

func Lookup(id string) (Task, bool) {
	for _, task := range Tasks() {
		if task.ID == id {
			return task, true
		}
	}
	return Task{}, false
}

func PathAllowed(t Task, p string) bool {
	matches := func(pattern string) bool {
		matched, err := path.Match(pattern, p)
		return err == nil && matched
	}
	return slices.ContainsFunc(t.WritablePaths, matches) && !slices.ContainsFunc(t.ExcludedPaths, matches)
}
