package patchcheck

import (
	"bytes"
	"fmt"
	"path"
	"regexp"
	"slices"
	"strings"
)

type Path struct {
	Name   string
	Binary bool
}

func ParseNumstat(data []byte) ([]Path, error) {
	var paths []Path
	for len(data) != 0 {
		entry, rest, ok := bytes.Cut(data, []byte{0})
		if !ok {
			return nil, fmt.Errorf("unterminated git numstat entry")
		}
		fields := bytes.SplitN(entry, []byte{'\t'}, 3)
		if len(fields) != 3 || len(fields[2]) == 0 {
			return nil, fmt.Errorf("invalid git numstat entry %q", entry)
		}
		paths = append(paths, Path{
			Name: string(fields[2]), Binary: string(fields[0]) == "-" || string(fields[1]) == "-",
		})
		data = rest
	}
	return paths, nil
}

// An unchanged file mode appears on the index line and is omitted by --summary.
var specialIndexMode = regexp.MustCompile(`(?m)^index [0-9a-fA-F]+\.\.[0-9a-fA-F]+[ \t]+0*1[26]0000(?:[^0-7]|$)`)

func ValidateRelativePaths(paths []Path) error {
	for _, entry := range paths {
		if UnsafeRelativePath(entry.Name) {
			return reject("unsafe patch path", entry.Name, "unsafe patch path %q", entry.Name)
		}
	}
	return nil
}

func UnsafeRelativePath(name string) bool {
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

func ValidatePaths(allowed func(string) bool, paths []Path, summary string, hasSpecialIndexMode bool) error {
	if len(paths) == 0 {
		return reject("empty patch", "", "patch touches no files")
	}
	if err := ValidateRelativePaths(paths); err != nil {
		return err
	}
	for _, entry := range paths {
		if !allowed(entry.Name) {
			return reject("path outside writable paths", entry.Name, "patch path %q is outside the task's writable paths", entry.Name)
		}
		if entry.Binary {
			return reject("binary patch", entry.Name, "binary patch for %q", entry.Name)
		}
	}
	modes := make(map[string]string)
	for line := range strings.SplitSeq(summary, "\n") {
		line = strings.TrimLeft(line, " \t")
		operation, details, _ := strings.Cut(line, " ")
		switch operation {
		case "rename", "copy", "mode":
			return reject("unsupported patch operation: "+operation, "", "unsupported patch operation: %s", line)
		case "create", "delete":
			modeAndName, ok := strings.CutPrefix(details, "mode ")
			if !ok {
				continue
			}
			mode, name, _ := strings.Cut(modeAndName, " ")
			if mode == "120000" || mode == "160000" {
				return reject("symlink or submodule patch", "", "symlink or submodule patch: %s", line)
			}
			if previous, exists := modes[name]; exists && mode != previous {
				return reject("mode change", "", "mode change for %q: %s and %s", name, previous, mode)
			}
			modes[name] = mode
		}
	}
	if hasSpecialIndexMode {
		return reject("patch edits a symlink or submodule", "", "patch edits a symlink or submodule")
	}
	return nil
}

func validateBaseModes(paths []Path, tree []byte) error {
	special := make(map[string]bool)
	for entry := range strings.SplitSeq(string(tree), "\x00") {
		mode, _, _ := strings.Cut(entry, " ")
		if mode == "120000" || mode == "160000" {
			_, name, _ := strings.Cut(entry, "\t")
			special[name] = true
		}
	}
	for _, entry := range paths {
		for name := entry.Name; name != "."; name = path.Dir(name) {
			if special[name] {
				return reject("patch touches a symlink or submodule", entry.Name, "patch path %q touches a symlink or submodule at %q", entry.Name, name)
			}
		}
	}
	return nil
}

func Inspect(product, baseCommit string, patch []byte, allowed func(path string) bool) ([]string, int, error) {
	numstat, err := Git(product, patch, "apply", "--numstat", "-z", "--")
	if err != nil {
		return nil, GitRejectionCode(err), err
	}
	summary, err := Git(product, patch, "apply", "--summary", "--")
	if err != nil {
		return nil, GitRejectionCode(err), err
	}
	paths, err := ParseNumstat(numstat)
	if err != nil {
		return nil, 2, err
	}
	if err := ValidatePaths(allowed, paths, string(summary), specialIndexMode.Match(patch)); err != nil {
		return nil, 1, err
	}
	// Inspect original paths too, since the usual prefix stripping can hide an
	// initial slash or a leading traversal component.
	raw, err := Git(product, patch, "apply", "-p0", "--numstat", "-z", "--")
	if err != nil {
		return nil, GitRejectionCode(err), err
	}
	rawPaths, err := ParseNumstat(raw)
	if err != nil {
		return nil, 2, err
	}
	if err := ValidateRelativePaths(rawPaths); err != nil {
		return nil, 1, err
	}
	tree, err := Git(product, nil, "ls-tree", "-rz", "--full-tree", baseCommit)
	if err != nil {
		return nil, 2, err
	}
	if err := validateBaseModes(paths, tree); err != nil {
		return nil, 1, err
	}
	names := make([]string, 0, len(paths))
	for _, entry := range paths {
		names = append(names, entry.Name)
	}
	slices.Sort(names)
	return slices.Compact(names), 0, nil
}

type Rejection struct {
	Category string
	Path     string
	message  string
}

func (r *Rejection) Error() string { return r.message }

func reject(category, path, format string, args ...any) error {
	return &Rejection{Category: category, Path: path, message: fmt.Sprintf(format, args...)}
}
