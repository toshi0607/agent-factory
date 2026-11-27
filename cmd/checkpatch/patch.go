package main

import (
	"path"

	"github.com/toshi0607/agent-factory/internal/patchcheck"
	"github.com/toshi0607/agent-factory/judge/google-cloud-emulator/p0"
)

func git(dir string, input []byte, args ...string) ([]byte, error) {
	return patchcheck.Git(dir, input, args...)
}

func taskAllows(task p0.Task, name string) bool {
	return p0.PathAllowed(task, name) && path.Base(name) != "unimplemented.json"
}

func inspectPatch(product, base string, task p0.Task, patch []byte) (int, error) {
	_, code, err := patchcheck.Inspect(product, base, patch, func(name string) bool { return taskAllows(task, name) })
	return code, err
}
