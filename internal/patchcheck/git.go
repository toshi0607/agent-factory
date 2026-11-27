package patchcheck

import (
	"bytes"
	"errors"
	"fmt"
	"io"
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
	cmd := gitCommand(dir, env, args)
	cmd.Stdin = bytes.NewReader(input)
	output, err := cmd.Output()
	if exited, ok := errors.AsType[*exec.ExitError](err); ok {
		return output, gitError(args, err, exited.Stderr)
	}
	if err != nil {
		return nil, gitError(args, err, nil)
	}
	return output, nil
}

// GitWithEnvLimit rejects command output larger than limit bytes.
func GitWithEnvLimit(dir string, env []string, limit int64, args ...string) ([]byte, error) {
	cmd := gitCommand(dir, env, args)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, gitError(args, err, nil)
	}
	output, err := io.ReadAll(io.LimitReader(stdout, limit+1))
	if err != nil || int64(len(output)) > limit {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("Git output exceeds %d bytes", limit)
	}
	if err := cmd.Wait(); err != nil {
		return nil, gitError(args, err, stderr.Bytes())
	}
	return output, nil
}

func gitCommand(dir string, env []string, args []string) *exec.Cmd {
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
	return cmd
}

func gitError(args []string, err error, stderr []byte) error {
	if len(stderr) != 0 {
		return fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(stderr)))
	}
	return fmt.Errorf("git %s: %w", strings.Join(args, " "), err)
}
