package main

import (
	"bytes"
	"fmt"
	"path"
	"regexp"
	"strings"

	"github.com/toshi0607/agent-factory/judge/google-cloud-emulator/p0"
)

type patchPath struct {
	name   string
	binary bool
}

func parseNumstat(data []byte) ([]patchPath, error) {
	var paths []patchPath
	for len(data) != 0 {
		entry, rest, ok := bytes.Cut(data, []byte{0})
		if !ok {
			return nil, fmt.Errorf("unterminated git numstat entry")
		}
		fields := bytes.SplitN(entry, []byte{'\t'}, 3)
		if len(fields) != 3 || len(fields[2]) == 0 {
			return nil, fmt.Errorf("invalid git numstat entry %q", entry)
		}
		paths = append(paths, patchPath{
			name: string(fields[2]), binary: string(fields[0]) == "-" || string(fields[1]) == "-",
		})
		data = rest
	}
	return paths, nil
}

// An unchanged file mode appears on the index line and is omitted by --summary.
var specialIndexMode = regexp.MustCompile(`(?m)^index [0-9a-fA-F]+\.\.[0-9a-fA-F]+[ \t]+0*1[26]0000(?:[^0-7]|$)`)

func validateRelativePaths(paths []patchPath) error {
	for _, entry := range paths {
		if unsafeRelativePath(entry.name) {
			return fmt.Errorf("unsafe patch path %q", entry.name)
		}
	}
	return nil
}

func unsafeRelativePath(name string) bool {
	if path.IsAbs(name) {
		return true
	}
	for component := range strings.SplitSeq(name, "/") {
		if component == ".." {
			return true
		}
	}
	return false
}

func validatePaths(task p0.Task, paths []patchPath, summary string, hasSpecialIndexMode bool) error {
	if len(paths) == 0 {
		return fmt.Errorf("patch touches no files")
	}
	if err := validateRelativePaths(paths); err != nil {
		return err
	}
	for _, entry := range paths {
		if !p0.PathAllowed(task, entry.name) || path.Base(entry.name) == "unimplemented.json" {
			return fmt.Errorf("patch path %q is outside the task's writable paths", entry.name)
		}
		if entry.binary {
			return fmt.Errorf("binary patch for %q", entry.name)
		}
	}
	modes := make(map[string]string)
	for line := range strings.SplitSeq(summary, "\n") {
		line = strings.TrimLeft(line, " \t")
		operation, details, _ := strings.Cut(line, " ")
		switch operation {
		case "rename", "copy", "mode":
			return fmt.Errorf("unsupported patch operation: %s", line)
		case "create", "delete":
			modeAndName, ok := strings.CutPrefix(details, "mode ")
			if !ok {
				continue
			}
			mode, name, _ := strings.Cut(modeAndName, " ")
			if mode == "120000" || mode == "160000" {
				return fmt.Errorf("symlink or submodule patch: %s", line)
			}
			if previous, exists := modes[name]; exists && mode != previous {
				return fmt.Errorf("mode change for %q: %s and %s", name, previous, mode)
			}
			modes[name] = mode
		}
	}
	if hasSpecialIndexMode {
		return fmt.Errorf("patch edits a symlink or submodule")
	}
	return nil
}

func validateBaseModes(paths []patchPath, tree []byte) error {
	special := make(map[string]bool)
	for entry := range strings.SplitSeq(string(tree), "\x00") {
		mode, _, _ := strings.Cut(entry, " ")
		if mode == "120000" || mode == "160000" {
			_, name, _ := strings.Cut(entry, "\t")
			special[name] = true
		}
	}
	for _, entry := range paths {
		for name := entry.name; name != "."; name = path.Dir(name) {
			if special[name] {
				return fmt.Errorf("patch path %q touches a symlink or submodule at %q", entry.name, name)
			}
		}
	}
	return nil
}
