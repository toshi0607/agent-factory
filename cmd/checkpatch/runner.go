package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"github.com/toshi0607/agent-factory/poc/record"
)

func judge(ctx context.Context, opt options, tree string, env []string, out *record.CheckResult, stderr io.Writer) (int, error) {
	genOut := filepath.Join(opt.work, "gen-out")
	genLog := filepath.Join(opt.work, "gen-script.log")
	code, err := runGeneration(ctx, opt, tree, genOut, genLog)
	switch {
	case err != nil:
		return 2, err
	case code == 10:
		return 1, fmt.Errorf("generation failed; see %s", filepath.Join(genOut, "gen.log"))
	case code != 0:
		return 2, fmt.Errorf("generation script exited %d; see %s", code, genLog)
	}
	if err := snapshotGeneration(opt.work, tree, env, out); err != nil {
		return 2, fmt.Errorf("snapshot generated worktree: %w", err)
	}

	checkOut, checkLog := filepath.Join(opt.work, "out"), filepath.Join(opt.work, "check-script.log")
	if opt.runner == "docker" {
		code, err = runDockerCheck(ctx, opt, tree, out, stderr)
	} else {
		code, err = runDirectCheck(ctx, opt, tree, checkOut, checkLog)
	}
	current, stageErr := stageTree(tree, env)
	if stageErr != nil {
		return 2, fmt.Errorf("snapshot worktree after check: %w", stageErr)
	}
	if current != out.JudgedTree {
		return 2, fmt.Errorf("worktree changed during check: got %s, judged %s", current, out.JudgedTree)
	}
	if err != nil {
		return code, err
	}
	if opt.runner == "docker" {
		return readJudgeResult(opt.taskID, filepath.Join(opt.work, "judge-out"), code, out)
	}
	return readDirectCheckResult(opt.taskID, checkOut, checkLog, code, out)
}

func runGeneration(ctx context.Context, opt options, tree, output, logPath string) (int, error) {
	if err := os.Mkdir(output, 0o755); err != nil {
		return 2, fmt.Errorf("create output directory: %w", err)
	}
	if opt.runner == "docker" {
		if err := os.Mkdir(filepath.Join(opt.work, "gen-gocache"), 0o755); err != nil {
			return 2, fmt.Errorf("create Go build cache: %w", err)
		}
		return runToLogs(ctx, logPath, logPath, 0, "docker", generationDockerArgs(opt, tree, output, os.Getuid(), os.Getgid())...)
	}
	return runToLogs(ctx, logPath, logPath, 0, "bash", opt.genScript, tree, output)
}

func runDirectCheck(ctx context.Context, opt options, tree, output, logPath string) (int, error) {
	if err := os.Mkdir(output, 0o755); err != nil {
		return 2, fmt.Errorf("create output directory: %w", err)
	}
	return runToLogs(ctx, logPath, logPath, 0, "bash", opt.script, tree, opt.taskID, opt.p0check, output)
}

func runToLogs(ctx context.Context, stdoutPath, stderrPath string, limit int, name string, args ...string) (code int, err error) {
	stdout, err := os.Create(stdoutPath)
	if err != nil {
		return 2, fmt.Errorf("create %s: %w", stdoutPath, err)
	}
	closeLog := func(file *os.File) {
		if closeErr := file.Close(); closeErr != nil {
			code, err = 2, errors.Join(err, closeErr)
		}
	}
	defer closeLog(stdout)
	stderr := stdout
	if stderrPath != stdoutPath {
		stderr, err = os.Create(stderrPath)
		if err != nil {
			return 2, fmt.Errorf("create %s: %w", stderrPath, err)
		}
		defer closeLog(stderr)
	}
	if limit > 0 {
		return runCommand(ctx, &cappedLog{stdout, limit}, &cappedLog{stderr, limit}, name, args...)
	}
	return runCommand(ctx, stdout, stderr, name, args...)
}

type cappedLog struct {
	file      *os.File
	remaining int
}

func (log *cappedLog) Write(data []byte) (int, error) {
	if size := min(len(data), log.remaining); size > 0 {
		n, err := log.file.Write(data[:size])
		log.remaining -= n
		if err != nil {
			return n, err
		}
	}
	return len(data), nil
}

func runCommand(ctx context.Context, stdout, stderr io.Writer, name string, args ...string) (int, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout, cmd.Stderr = stdout, stderr
	cmd.WaitDelay = 2 * time.Second
	runErr := cmd.Run()
	if err := ctx.Err(); err != nil {
		return 2, fmt.Errorf("run %s: %w", name, err)
	}
	if exited, ok := errors.AsType[*exec.ExitError](runErr); ok {
		return exited.ExitCode(), nil
	}
	if runErr != nil {
		return 2, fmt.Errorf("run %s: %w", name, runErr)
	}
	return 0, nil
}

func readDirectCheckResult(task, output, logPath string, code int, out *record.CheckResult) (int, error) {
	switch code {
	case 11:
		return 1, fmt.Errorf("build failed; see %s", filepath.Join(output, "build.log"))
	case 12:
		out.BuildOK = true
		return 1, fmt.Errorf("emulator did not announce its address; see %s", filepath.Join(output, "emulator.log"))
	case 13:
		out.BuildOK = true
		return 1, fmt.Errorf("p0check could not run; see %s", filepath.Join(output, "p0check.log"))
	case 0, 1:
		out.BuildOK = true
	default:
		return 2, fmt.Errorf("check script exited %d; see %s", code, logPath)
	}
	return readJudgeResult(task, output, code, out)
}

func readJudgeResult(task, output string, code int, out *record.CheckResult) (int, error) {
	data, err := readCheckOutput(output)
	if err != nil {
		return 2, fmt.Errorf("read p0check result: %w", err)
	}
	var result struct {
		Task     string           `json:"task"`
		Passed   bool             `json:"passed"`
		Failures []record.Failure `json:"failures"`
	}
	if err := json.Unmarshal(data, &result); err != nil {
		return 2, fmt.Errorf("decode p0check result: %w", err)
	}
	if result.Task != task || result.Failures == nil || result.Passed != (code == 0) ||
		result.Passed != (len(result.Failures) == 0) {
		return 2, fmt.Errorf("inconsistent p0check result for %q with exit code %d", task, code)
	}
	out.Failures = append(out.Failures, result.Failures...)
	out.CheckPassed = result.Passed
	return code, nil
}

func readCheckOutput(output string) ([]byte, error) {
	root, err := os.OpenRoot(output)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	const name = "p0check.json"
	info, err := root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("expected regular output file %s", name)
	}
	// Recheck the opened file and avoid following a symlink or blocking on a FIFO.
	file, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err = file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("expected regular output file %s", name)
	}
	const maxCheckOutputSize = 1 << 20
	data, err := io.ReadAll(io.LimitReader(file, maxCheckOutputSize+1))
	if err == nil && len(data) > maxCheckOutputSize {
		return nil, fmt.Errorf("%s exceeds %d bytes", name, maxCheckOutputSize)
	}
	return data, err
}
