package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/toshi0607/agent-factory/internal/patchcheck"
	"github.com/toshi0607/agent-factory/judge/google-cloud-emulator/p0"
	"github.com/toshi0607/agent-factory/poc/record"
)

type options struct {
	product, taskID, p0check, work, patch, script, genScript string
	archive, runner, image, modcache, buildScript            string
	noPatch                                                  bool
}

const (
	gitName  = "user.name=checkpatch"
	gitEmail = "user.email=checkpatch@invalid"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	out, code := run(ctx, os.Args[1:], os.Stderr)
	stop()
	if err := json.NewEncoder(os.Stdout).Encode(out); err != nil {
		fmt.Fprintln(os.Stderr, err)
		code = 2
	}
	os.Exit(code)
}

func run(ctx context.Context, args []string, stderr io.Writer) (record.CheckResult, int) {
	var opt options
	flags := flag.NewFlagSet("checkpatch", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() {
		fmt.Fprintln(stderr, "usage: checkpatch (-product <dir> | -product-archive <tar.gz>) -task <id> -p0check <bin> -work <dir> (-patch <file> | -no-patch) [-gen-script <file>] (-runner direct [-script <file>] | -runner docker -image <ref> -modcache <dir> [-build-script <file>])")
	}
	flags.StringVar(&opt.product, "product", "", "product repository")
	flags.StringVar(&opt.archive, "product-archive", "", "product Git archive (.tar.gz)")
	flags.StringVar(&opt.taskID, "task", "", "task ID")
	flags.StringVar(&opt.p0check, "p0check", "", "p0check binary")
	flags.StringVar(&opt.work, "work", "", "empty work directory")
	flags.StringVar(&opt.patch, "patch", "", "patch file")
	flags.BoolVar(&opt.noPatch, "no-patch", false, "check the baseline without a patch")
	flags.StringVar(&opt.genScript, "gen-script", "scripts/p0-gen-tree.sh", "generation script")
	flags.StringVar(&opt.script, "script", "scripts/p0-check-tree.sh", "direct check script")
	flags.StringVar(&opt.buildScript, "build-script", "scripts/p0-build-tree.sh", "Docker build script")
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
		opt.work == "" || opt.genScript == "" || opt.noPatch == (opt.patch != "") ||
		(opt.runner != "direct" && opt.runner != "docker") ||
		(opt.runner == "direct" && opt.script == "") ||
		(opt.runner == "docker" && (opt.image == "" || strings.HasPrefix(opt.image, "-") || opt.modcache == "" || opt.buildScript == "")) {
		flags.Usage()
		out.Error = "invalid arguments"
		return out, 2
	}
	out.Runner = opt.runner
	for _, name := range []*string{&opt.product, &opt.work, &opt.p0check, &opt.script, &opt.genScript, &opt.modcache, &opt.buildScript} {
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

	code, err := check(ctx, opt, &out, stderr)
	if err != nil {
		out.Error = err.Error()
	}
	return out, code
}

func check(ctx context.Context, opt options, out *record.CheckResult, stderr io.Writer) (int, error) {
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

	if err := createWorkDir(opt.work); err != nil {
		return 2, err
	}
	privateRepo, err := prepareRepository(opt)
	if err != nil {
		return 2, err
	}

	head, err := git(privateRepo, nil, "rev-parse", "--verify", "HEAD^{commit}")
	if err != nil {
		return 2, err
	}
	baseCommit := strings.TrimSpace(string(head))
	if !opt.noPatch {
		if code, err := inspectPatch(privateRepo, baseCommit, task, patch); err != nil {
			return code, err
		}
	}
	out.PathsOK = true

	tree := filepath.Join(opt.work, "tree")
	if err := os.Mkdir(tree, 0o755); err != nil {
		return 2, fmt.Errorf("create worktree: %w", err)
	}
	env := append(patchcheck.WorkTreeEnv(filepath.Join(privateRepo, ".git"), tree), "GIT_ALLOW_PROTOCOL=")
	if _, err := patchcheck.GitWithEnv(tree, nil, env, "read-tree", baseCommit); err != nil {
		return 2, err
	}
	if _, err := patchcheck.GitWithEnv(tree, nil, env, "checkout-index", "--all", "--index"); err != nil {
		return 2, err
	}
	if !opt.noPatch {
		if _, err := patchcheck.GitWithEnv(tree, patch, env, "apply", "--index", "--"); err != nil {
			return patchcheck.GitRejectionCode(err), err
		}
		if _, err := patchcheck.GitWithEnv(tree, nil, env, "-c", gitName, "-c", gitEmail,
			"commit", "--no-gpg-sign", "-m", "Apply candidate patch"); err != nil {
			return 2, err
		}
	}
	out.ApplyOK = true
	return judge(ctx, opt, tree, env, out, stderr)
}

func prepareRepository(opt options) (string, error) {
	if opt.archive != "" {
		base := filepath.Join(opt.work, "base")
		return base, initArchive(opt.archive, base)
	}
	repo := filepath.Join(opt.work, "repository")
	if _, err := git(opt.work, nil, "clone", "--no-hardlinks", "--no-checkout", "--", opt.product, repo); err != nil {
		return "", err
	}
	return repo, configureRepository(repo)
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
