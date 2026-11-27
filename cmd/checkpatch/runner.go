package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"

	"github.com/toshi0607/agent-factory/poc/record"
)

func judge(opt options, tree string, env []string, out *record.CheckResult) (int, error) {
	genOut, checkOut := filepath.Join(opt.work, "gen-out"), filepath.Join(opt.work, "out")
	genLog := filepath.Join(opt.work, "gen-script.log")
	code, err := runPhase(opt, true, tree, genOut, genLog)
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

	checkLog := filepath.Join(opt.work, "check-script.log")
	code, runErr := runPhase(opt, false, tree, checkOut, checkLog)
	if runErr != nil {
		return 2, runErr
	}
	current, err := stageTree(tree, env)
	if err != nil {
		return 2, fmt.Errorf("snapshot worktree after check: %w", err)
	}
	if current != out.JudgedTree {
		return 2, fmt.Errorf("worktree changed during check: got %s, judged %s", current, out.JudgedTree)
	}
	return readCheckResult(opt.taskID, checkOut, checkLog, code, out)
}

func runPhase(opt options, generation bool, tree, output, logPath string) (int, error) {
	if err := os.Mkdir(output, 0o755); err != nil {
		return 2, fmt.Errorf("create output directory: %w", err)
	}
	cmd := exec.Command("bash", opt.script, tree, opt.taskID, opt.p0check, output)
	if generation {
		cmd = exec.Command("bash", opt.genScript, tree, output)
	}
	if opt.runner == "docker" {
		if err := os.Mkdir(buildCache(opt.work, generation), 0o755); err != nil {
			return 2, fmt.Errorf("create Go build cache: %w", err)
		}
		cmd = exec.Command("docker", dockerArgs(opt, generation, tree, output, os.Getuid(), os.Getgid())...)
	}
	log, err := os.Create(logPath)
	if err != nil {
		return 2, fmt.Errorf("create script log: %w", err)
	}
	cmd.Stdout, cmd.Stderr = log, log
	runErr := cmd.Run()
	if err := log.Close(); err != nil {
		return 2, fmt.Errorf("close script log: %w", err)
	}
	if exited, ok := errors.AsType[*exec.ExitError](runErr); ok {
		return exited.ExitCode(), nil
	}
	if runErr != nil {
		return 2, fmt.Errorf("run script: %w", runErr)
	}
	return 0, nil
}

func readCheckResult(task, output, logPath string, code int, out *record.CheckResult) (int, error) {
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
	return io.ReadAll(file)
}

func buildCache(work string, generation bool) string {
	if generation {
		return filepath.Join(work, "gen-gocache")
	}
	return filepath.Join(work, "gocache")
}

func dockerArgs(opt options, generation bool, tree, output string, uid, gid int) []string {
	args := []string{
		"run", "--rm", "--network", "none", "--cap-drop", "ALL",
		"--security-opt", "no-new-privileges", "--pids-limit", "1024", "--memory", "4g",
		"--user", strconv.Itoa(uid) + ":" + strconv.Itoa(gid), "--tmpfs", "/tmp:rw,exec,size=512m",
		"-e", "HOME=/tmp", "-e", "GOCACHE=/gocache", "-e", "GOMODCACHE=/modcache",
		"-e", "GOFLAGS=-mod=readonly", "-e", "GOPROXY=off", "-e", "GOTOOLCHAIN=local",
		"-v", output + ":/out", "-v", buildCache(opt.work, generation) + ":/gocache",
		"-w", "/tree",
	}
	if generation {
		return append(args, "-v", tree+":/tree", "-v", opt.modcache+":/modcache:ro",
			"-v", opt.genScript+":/p0-gen-tree.sh:ro",
			opt.image, "bash", "/p0-gen-tree.sh", "/tree", "/out")
	}
	return append(args, "-v", tree+":/tree:ro", "-v", opt.modcache+":/modcache",
		"-v", opt.p0check+":/p0check:ro", "-v", opt.script+":/p0-check-tree.sh:ro",
		opt.image, "bash", "/p0-check-tree.sh", "/tree", opt.taskID, "/p0check", "/out")
}
