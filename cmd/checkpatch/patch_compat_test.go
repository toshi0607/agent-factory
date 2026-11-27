package main

import (
	"github.com/toshi0607/agent-factory/internal/patchcheck"
	"github.com/toshi0607/agent-factory/judge/google-cloud-emulator/p0"
)

type patchPath struct {
	name   string
	binary bool
}

func parseNumstat(data []byte) ([]patchPath, error) {
	entries, err := patchcheck.ParseNumstat(data)
	paths := make([]patchPath, 0, len(entries))
	for _, entry := range entries {
		paths = append(paths, patchPath{name: entry.Name, binary: entry.Binary})
	}
	return paths, err
}

func sharedPaths(paths []patchPath) []patchcheck.Path {
	entries := make([]patchcheck.Path, 0, len(paths))
	for _, entry := range paths {
		entries = append(entries, patchcheck.Path{Name: entry.name, Binary: entry.binary})
	}
	return entries
}

func validateRelativePaths(paths []patchPath) error {
	return patchcheck.ValidateRelativePaths(sharedPaths(paths))
}

func validatePaths(task p0.Task, paths []patchPath, summary string, special bool) error {
	return patchcheck.ValidatePaths(func(name string) bool { return taskAllows(task, name) }, sharedPaths(paths), summary, special)
}
