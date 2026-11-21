package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/toshi0607/agent-factory/judge/google-cloud-emulator/p0"
	"github.com/toshi0607/agent-factory/poc/record"
)

type options struct {
	product, taskID, p0check, work, patch, script string
	archive, runner, image, modcache              string
	noPatch                                       bool
}

const (
	gitName  = "user.name=checkpatch"
	gitEmail = "user.email=checkpatch@invalid"
)

func main() {
	out, code := run(os.Args[1:], os.Stderr)
	if err := json.NewEncoder(os.Stdout).Encode(out); err != nil {
		fmt.Fprintln(os.Stderr, err)
		code = 2
	}
	os.Exit(code)
}

func run(args []string, stderr io.Writer) (record.CheckResult, int) {
	var opt options
	flags := flag.NewFlagSet("checkpatch", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() {
		fmt.Fprintln(stderr, "usage: checkpatch (-product <dir> | -product-archive <tar.gz>) -task <id> -p0check <bin> -work <dir> (-patch <file> | -no-patch) (-runner direct | -runner docker -image <ref> -modcache <dir>) [-script <file>]")
	}
	flags.StringVar(&opt.product, "product", "", "product repository")
	flags.StringVar(&opt.archive, "product-archive", "", "product Git archive (.tar.gz)")
	flags.StringVar(&opt.taskID, "task", "", "task ID")
	flags.StringVar(&opt.p0check, "p0check", "", "p0check binary")
	flags.StringVar(&opt.work, "work", "", "empty work directory")
	flags.StringVar(&opt.patch, "patch", "", "patch file")
	flags.BoolVar(&opt.noPatch, "no-patch", false, "check the baseline without a patch")
	flags.StringVar(&opt.script, "script", "scripts/p0-check-tree.sh", "check script")
	flags.StringVar(&opt.runner, "runner", "", "required check runner: direct or docker")
	flags.StringVar(&opt.image, "image", "", "Docker image for the check")
	flags.StringVar(&opt.modcache, "modcache", "", "populated Go module cache for Docker")

	parseErr := flags.Parse(args)
	out := record.CheckResult{Task: opt.taskID, GenChangedPaths: []string{}, Failures: []record.Failure{}}
	if parseErr != nil {
		out.Error = parseErr.Error()
		return out, 2
	}
	if flags.NArg() != 0 || (opt.product == "") == (opt.archive == "") || opt.taskID == "" || opt.p0check == "" ||
		opt.work == "" || opt.script == "" || opt.noPatch == (opt.patch != "") ||
		(opt.runner != "direct" && opt.runner != "docker") ||
		(opt.runner == "docker" && (opt.image == "" || strings.HasPrefix(opt.image, "-") || opt.modcache == "")) {
		flags.Usage()
		out.Error = "invalid arguments"
		return out, 2
	}
	for _, name := range []*string{&opt.product, &opt.work, &opt.p0check, &opt.script, &opt.modcache} {
		if *name == "" {
			continue
		}
		abs, err := filepath.Abs(*name)
		if err != nil {
			out.Error = fmt.Sprintf("resolve %q: %v", *name, err)
			return out, 2
		}
		*name = abs
	}

	code, err := check(opt, &out)
	if err != nil {
		out.Error = err.Error()
	}
	return out, code
}

func check(opt options, out *record.CheckResult) (int, error) {
	task, known := p0.Lookup(opt.taskID)
	var patch []byte
	if !opt.noPatch {
		var err error
		patch, err = os.ReadFile(opt.patch)
		if err == nil {
			out.PatchSHA256 = fmt.Sprintf("%x", sha256.Sum256(patch))
		} else if known {
			return 2, fmt.Errorf("read patch: %w", err)
		}
	}
	if !known {
		return 2, fmt.Errorf("unknown task %q", opt.taskID)
	}

	if opt.archive != "" {
		if err := createWorkDir(opt.work); err != nil {
			return 2, err
		}
		opt.product = filepath.Join(opt.work, "base")
		if err := initArchive(opt.archive, opt.product); err != nil {
			return 2, err
		}
	}
	head, err := git(opt.product, nil, "rev-parse", "--verify", "HEAD^{commit}")
	if err != nil {
		return 2, err
	}
	baseCommit := strings.TrimSpace(string(head))
	if !opt.noPatch {
		if code, err := inspectPatch(opt.product, baseCommit, task, patch); err != nil {
			return code, err
		}
	}
	out.PathsOK = true

	if opt.archive == "" {
		if err := createWorkDir(opt.work); err != nil {
			return 2, err
		}
	}

	tree, output := filepath.Join(opt.work, "tree"), filepath.Join(opt.work, "out")
	if _, err := git(opt.work, nil, "clone", "--no-hardlinks", "--no-checkout", "--", opt.product, tree); err != nil {
		return 2, err
	}
	if _, err := git(tree, nil, "-c", "core.hooksPath=/dev/null", "checkout", "--detach", baseCommit); err != nil {
		return 2, err
	}
	if !opt.noPatch {
		if _, err := git(tree, patch, "apply", "--index", "--"); err != nil {
			return gitRejectionCode(err), err
		}
		if _, err := git(tree, nil, "-c", gitName, "-c", gitEmail,
			"-c", "core.hooksPath=/dev/null", "commit", "--no-gpg-sign", "-m", "Apply candidate patch"); err != nil {
			return 2, err
		}
	}
	out.ApplyOK = true

	return runCheckScript(opt, tree, output, out)
}

func createWorkDir(work string) error {
	if err := os.MkdirAll(work, 0o755); err != nil {
		return fmt.Errorf("create work directory: %w", err)
	}
	entries, err := os.ReadDir(work)
	if err != nil {
		return fmt.Errorf("read work directory: %w", err)
	}
	if len(entries) != 0 {
		return fmt.Errorf("work directory must be empty: %s", work)
	}
	return nil
}

func inspectPatch(product, base string, task p0.Task, patch []byte) (int, error) {
	numstat, err := git(product, patch, "apply", "--numstat", "-z", "--")
	if err != nil {
		return gitRejectionCode(err), err
	}
	summary, err := git(product, patch, "apply", "--summary", "--")
	if err != nil {
		return gitRejectionCode(err), err
	}
	paths, err := parseNumstat(numstat)
	if err != nil {
		return 2, err
	}
	if err := validatePaths(task, paths, string(summary), specialIndexMode.Match(patch)); err != nil {
		return 1, err
	}
	// Inspect original paths too, since the usual prefix stripping can hide an
	// initial slash or a leading traversal component.
	raw, err := git(product, patch, "apply", "-p0", "--numstat", "-z", "--")
	if err != nil {
		return gitRejectionCode(err), err
	}
	rawPaths, err := parseNumstat(raw)
	if err != nil {
		return 2, err
	}
	if err := validateRelativePaths(rawPaths); err != nil {
		return 1, err
	}
	tree, err := git(product, nil, "ls-tree", "-rz", "--full-tree", base)
	if err != nil {
		return 2, err
	}
	if err := validateBaseModes(paths, tree); err != nil {
		return 1, err
	}
	return 0, nil
}

func gitRejectionCode(err error) int {
	if _, ok := errors.AsType[*exec.ExitError](err); ok {
		return 1
	}
	return 2
}

func git(dir string, input []byte, args ...string) ([]byte, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(slices.DeleteFunc(cmd.Environ(), func(entry string) bool {
		key, _, _ := strings.Cut(entry, "=")
		switch key {
		case "GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_COMMON_DIR", "GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES":
			return true
		default:
			return false
		}
	}), "LC_ALL=C")
	cmd.Stdin = bytes.NewReader(input)
	output, err := cmd.Output()
	if exited, ok := errors.AsType[*exec.ExitError](err); ok {
		return nil, fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(exited.Stderr)))
	}
	if err != nil {
		return nil, fmt.Errorf("git %s: %w", strings.Join(args, " "), err)
	}
	return output, nil
}

func runCheckScript(opt options, tree, output string, out *record.CheckResult) (int, error) {
	if err := os.Mkdir(output, 0o755); err != nil {
		return 2, fmt.Errorf("create output directory: %w", err)
	}
	if opt.runner == "docker" {
		if err := os.Mkdir(filepath.Join(opt.work, "gocache"), 0o755); err != nil {
			return 2, fmt.Errorf("create Go build cache: %w", err)
		}
	}
	logPath := filepath.Join(output, "script.log")
	log, err := os.Create(logPath)
	if err != nil {
		return 2, fmt.Errorf("create script log: %w", err)
	}
	cmd := exec.Command("bash", opt.script, tree, opt.taskID, opt.p0check, output)
	if opt.runner == "docker" {
		cmd = exec.Command("docker", dockerArgs(opt, tree, output, os.Getuid(), os.Getgid())...)
	}
	cmd.Stdout, cmd.Stderr = log, log
	runErr := cmd.Run()
	if err := log.Close(); err != nil {
		return 2, fmt.Errorf("close script log: %w", err)
	}
	var scriptCode int
	if runErr != nil {
		exited, ok := errors.AsType[*exec.ExitError](runErr)
		if !ok {
			return 2, fmt.Errorf("run check script: %w", runErr)
		}
		scriptCode = exited.ExitCode()
	}
	switch scriptCode {
	case 10:
		return 1, fmt.Errorf("generation failed; see %s", filepath.Join(output, "gen.log"))
	case 0, 1, 11, 12, 13:
		out.GenOK = true
		out.BuildOK = scriptCode != 11
	default:
		return 2, fmt.Errorf("check script exited %d; see %s", scriptCode, logPath)
	}

	readOutput := func(name string) ([]byte, error) {
		return os.ReadFile(filepath.Join(output, name))
	}
	if opt.runner == "docker" {
		root, err := os.OpenRoot(output)
		if err != nil {
			return 2, fmt.Errorf("open output directory: %w", err)
		}
		defer root.Close()
		readOutput = func(name string) ([]byte, error) { return readCheckOutput(root, name) }
	}
	data, err := readOutput("gen-changed-paths.txt")
	if err != nil {
		return 2, fmt.Errorf("read generation paths: %w", err)
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		if line != "" {
			out.GenChangedPaths = append(out.GenChangedPaths, line)
		}
	}
	switch scriptCode {
	case 11:
		return 1, fmt.Errorf("build failed; see %s", filepath.Join(output, "build.log"))
	case 12:
		return 1, fmt.Errorf("emulator did not announce its address; see %s", filepath.Join(output, "emulator.log"))
	case 13:
		return 1, fmt.Errorf("p0check could not run; see %s", filepath.Join(output, "p0check.log"))
	}
	data, err = readOutput("p0check.json")
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
	if result.Task != opt.taskID || result.Failures == nil || result.Passed != (scriptCode == 0) ||
		result.Passed != (len(result.Failures) == 0) {
		return 2, fmt.Errorf("inconsistent p0check result for %q with exit code %d", opt.taskID, scriptCode)
	}
	out.Failures = append(out.Failures, result.Failures...)
	out.CheckPassed = result.Passed
	return scriptCode, nil
}

func readCheckOutput(root *os.Root, name string) ([]byte, error) {
	info, err := root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("expected regular output file %s", name)
	}
	return root.ReadFile(name)
}

func dockerArgs(opt options, tree, output string, uid, gid int) []string {
	return []string{
		"run", "--rm", "--network", "none", "--cap-drop", "ALL",
		"--security-opt", "no-new-privileges", "--pids-limit", "1024", "--memory", "4g",
		"--user", strconv.Itoa(uid) + ":" + strconv.Itoa(gid), "--tmpfs", "/tmp:rw,exec,size=512m",
		"-e", "HOME=/tmp", "-e", "GOCACHE=/gocache", "-e", "GOMODCACHE=/modcache",
		"-e", "GOFLAGS=-mod=readonly", "-e", "GOPROXY=off", "-e", "GOTOOLCHAIN=local",
		"-v", tree + ":/tree", "-v", output + ":/out", "-v", opt.modcache + ":/modcache",
		"-v", filepath.Join(opt.work, "gocache") + ":/gocache",
		"-v", opt.p0check + ":/p0check:ro", "-v", opt.script + ":/p0-check-tree.sh:ro",
		"-w", "/tree", opt.image, "bash", "/p0-check-tree.sh", "/tree", opt.taskID, "/p0check", "/out",
	}
}
