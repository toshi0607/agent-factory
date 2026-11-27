package policy

import (
	"errors"
	"fmt"
	"slices"
	"strings"
)

type Reflect struct {
	TargetRefs           []string `yaml:"target_refs"`
	DefaultBranchAllowed bool     `yaml:"default_branch_allowed"`
	Generated            []string `yaml:"generated"`
	GeneratedOutputs     []string `yaml:"generated_outputs"`
	DependencyFiles      []string `yaml:"dependency_files"`
	Protected            []string `yaml:"protected"`
}

const builtInProtected = ".github/** AGENTS.md **/AGENTS.md CLAUDE.md **/CLAUDE.md .claude/** **/.claude/** .codex/** **/.codex/** .git/** .gitmodules .gitattributes **/.gitattributes"

func (p Policy) RoleMayWrite(role, path string) bool {
	return !p.Protected(path) && !p.Generated(path) && !p.DependencyFile(path) && matchesAny(p.Roles[role].Write, path)
}

func (p Policy) Generated(path string) bool {
	return matchesAny(p.Reflect.Generated, path)
}

func (p Policy) GeneratedOutput(path string) bool {
	return matchesAny(p.Reflect.GeneratedOutputs, path)
}

func (p Policy) Protected(path string) bool {
	for pattern := range strings.FieldsSeq(builtInProtected) {
		if MatchPath(pattern, path) {
			return true
		}
	}
	return matchesAny(p.Reflect.Protected, path)
}

func (p Policy) DependencyFile(path string) bool {
	return matchesAny(p.Reflect.DependencyFiles, path)
}

func (p Policy) TargetRefAllowed(ref string) bool {
	return validTargetRef(ref) && slices.Contains(p.Reflect.TargetRefs, ref)
}

func (p Policy) validateReflect() error {
	for _, ref := range p.Reflect.TargetRefs {
		if !validTargetRef(ref) {
			return fmt.Errorf("reflect.target_refs contains an invalid exact ref %q", ref)
		}
	}
	for _, field := range []struct {
		name     string
		patterns []string
	}{
		{"reflect.generated", p.Reflect.Generated},
		{"reflect.generated_outputs", p.Reflect.GeneratedOutputs},
		{"reflect.dependency_files", p.Reflect.DependencyFiles},
		{"reflect.protected", p.Reflect.Protected},
	} {
		if err := validatePatterns(field.name, field.patterns); err != nil {
			return err
		}
	}
	if len(p.Reflect.Generated) != 0 && len(p.Reflect.GeneratedOutputs) == 0 {
		return errors.New("reflect.generated_outputs is required when reflect.generated is non-empty")
	}
	for name, role := range p.Roles {
		if err := validatePatterns(fmt.Sprintf("role %q write", name), role.Write); err != nil {
			return err
		}
		if len(role.Write) != 0 && len(p.Reflect.TargetRefs) == 0 {
			return errors.New("reflect.target_refs is required when a role has write patterns")
		}
	}
	return nil
}

func validTargetRef(ref string) bool {
	if !strings.HasPrefix(ref, "refs/heads/") || strings.HasSuffix(ref, ".") ||
		strings.Contains(ref, "..") || strings.Contains(ref, "@{") ||
		strings.ContainsAny(ref, " ~^:?*[\\") {
		return false
	}
	for _, b := range []byte(ref) {
		if b < ' ' || b == 0x7f {
			return false
		}
	}
	for part := range strings.SplitSeq(ref, "/") {
		if part == "" || strings.HasPrefix(part, ".") || strings.HasSuffix(part, ".lock") {
			return false
		}
	}
	return true
}

func validatePatterns(field string, patterns []string) error {
	if len(patterns) > 64 {
		return fmt.Errorf("%s allows at most 64 patterns", field)
	}
	for _, pattern := range patterns {
		for part := range strings.SplitSeq(pattern, "/") {
			if part == "" || part == "." || part == ".." || strings.ContainsAny(part, "?[{\\\x00") {
				return fmt.Errorf("%s contains invalid path pattern %q", field, pattern)
			}
		}
	}
	return nil
}

func matchesAny(patterns []string, path string) bool {
	return slices.ContainsFunc(patterns, func(pattern string) bool { return MatchPath(pattern, path) })
}

// MatchPath is case-sensitive and byte-exact, with no Unicode normalization.
func MatchPath(pattern, path string) bool {
	names := strings.Split(path, "/")
	matches := make([]bool, len(names)+1)
	matches[0] = true
	for part := range strings.SplitSeq(pattern, "/") {
		if part == "**" {
			for i := range names {
				matches[i+1] = matches[i+1] || (matches[i] && names[i] != "")
			}
			continue
		}
		for i := len(names); i > 0; i-- {
			matches[i] = matches[i-1] && names[i-1] != "" && matchSegment(part, names[i-1])
		}
		matches[0] = false
	}
	return matches[len(names)]
}

func matchSegment(pattern, name string) bool {
	prefix, rest, wildcard := strings.Cut(pattern, "*")
	if !wildcard {
		return prefix == name
	}
	name, matched := strings.CutPrefix(name, prefix)
	if !matched {
		return false
	}
	for {
		part, remaining, more := strings.Cut(rest, "*")
		if !more {
			return strings.HasSuffix(name, part)
		}
		_, name, matched = strings.Cut(name, part)
		if !matched {
			return false
		}
		rest = remaining
	}
}
