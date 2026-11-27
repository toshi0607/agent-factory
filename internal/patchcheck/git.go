package patchcheck

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
)

func GitRejectionCode(err error) int {
	if _, ok := errors.AsType[*exec.ExitError](err); ok {
		return 1
	}
	return 2
}

func Git(dir string, input []byte, args ...string) ([]byte, error) {
	return GitWithEnv(dir, input, nil, args...)
}

// GitWithEnv adds only caller-supplied environment entries to the scrubbed environment.
func GitWithEnv(dir string, input []byte, env []string, args ...string) ([]byte, error) {
	config := []string{
		"-c", "core.hooksPath=/dev/null",
		"-c", "core.fsmonitor=false",
		"-c", "core.attributesFile=/dev/null",
	}
	cmd := exec.Command("git", append(config, args...)...)
	cmd.Dir = dir
	searchPath := slices.DeleteFunc(filepath.SplitList(os.Getenv("PATH")), func(dir string) bool {
		return !filepath.IsAbs(dir)
	})
	cmd.Env = []string{
		"PATH=" + strings.Join(searchPath, string(os.PathListSeparator)), "LC_ALL=C",
		"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_ATTR_NOSYSTEM=1",
		"GIT_NO_REPLACE_OBJECTS=1", "GIT_NO_LAZY_FETCH=1", "GIT_TERMINAL_PROMPT=0",
		"GIT_PROTOCOL_FROM_USER=0", "GIT_ALLOW_PROTOCOL=file",
	}
	cmd.Env = append(cmd.Env, env...)
	cmd.Stdin = bytes.NewReader(input)
	output, err := cmd.Output()
	if exited, ok := errors.AsType[*exec.ExitError](err); ok {
		return output, fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(exited.Stderr)))
	}
	if err != nil {
		return nil, fmt.Errorf("git %s: %w", strings.Join(args, " "), err)
	}
	return output, nil
}
