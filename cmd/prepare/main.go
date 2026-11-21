package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/toshi0607/agent-factory/internal/delivery"
	"github.com/toshi0607/agent-factory/internal/policy"
)

const publicProxy = "https://proxy.golang.org"

type options struct {
	policy, product, task, out string
}

type preparer struct {
	http      *http.Client
	proxyBase string
	goList    func(context.Context, string) (string, error)
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	p := preparer{http: http.DefaultClient, proxyBase: publicProxy, goList: listDependencies}
	if err := p.run(ctx, os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "prepare:", err)
		os.Exit(1)
	}
}

var taskID = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]*$`)

func (p preparer) run(ctx context.Context, args []string) error {
	var opts options
	flags := flag.NewFlagSet("prepare", flag.ContinueOnError)
	flags.StringVar(&opts.policy, "policy", "", "policy file")
	flags.StringVar(&opts.product, "product", "", "product checkout")
	flags.StringVar(&opts.task, "task", "", "task ID")
	flags.StringVar(&opts.out, "out", "", "delivery directory")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || opts.policy == "" || opts.product == "" || opts.task == "" || opts.out == "" {
		return errors.New("usage: prepare -policy <file> -product <dir> -task <id> -out <dir>")
	}
	if !taskID.MatchString(opts.task) {
		return errors.New("invalid task ID")
	}
	return p.prepare(ctx, opts)
}

func (p preparer) prepare(ctx context.Context, opts options) error {
	cfg, err := policy.Load(opts.policy)
	if err != nil {
		return err
	}
	base, err := commandOutput(exec.CommandContext(ctx, "git", "-C", opts.product, "rev-parse", "HEAD"))
	if err != nil {
		return err
	}
	status, err := commandOutput(exec.CommandContext(ctx, "git", "--no-optional-locks", "-C", opts.product, "status", "--porcelain", "--untracked-files=all"))
	if err != nil {
		return err
	}
	if status != "" {
		return errors.New("product tree is dirty")
	}
	out, err := filepath.Abs(opts.out)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(out, 0o755); err != nil {
		return err
	}
	manifestPath := filepath.Join(out, delivery.ManifestName)
	if err := removeIfPresent(manifestPath); err != nil {
		return err
	}

	if err := p.prepareToolchain(ctx, out, cfg.Toolchain.Go); err != nil {
		return err
	}
	base = strings.TrimSpace(base)
	// Archive the same revision whose ID goes in the manifest.
	archive := exec.CommandContext(ctx, "git", "-C", opts.product, "archive", "--format=tar.gz",
		"-o", filepath.Join(out, "product.tar.gz"), base)
	if _, err := commandOutput(archive); err != nil {
		return err
	}

	deps, err := p.goList(ctx, opts.product)
	if err != nil {
		return err
	}
	hasProxy, err := p.prepareModules(ctx, out, deps, cfg.Product.Module)
	if err != nil {
		return err
	}

	for _, item := range []struct{ source, name string }{
		{"sandbox/setup.sh", "setup.sh"},
		{"sandbox/finish.sh", "finish.sh"},
		{"sandbox/probe.sh", "probe.sh"},
		{filepath.Join("poc", "tasks", opts.task+".md"), "task.md"},
	} {
		if err := copyFile(item.source, filepath.Join(out, item.name)); err != nil {
			return err
		}
	}
	names := []string{"setup.sh", "finish.sh", "probe.sh", "task.md", "product.tar.gz", cfg.Toolchain.Go.Filename}
	if hasProxy {
		names = append(names, "modproxy.tar.gz")
	}
	manifest := delivery.Manifest{Task: opts.task, BaseCommit: base}
	for _, name := range names {
		file, err := delivery.Inspect(filepath.Join(out, name))
		if err != nil {
			return err
		}
		manifest.Files = append(manifest.Files, file)
	}
	return delivery.WriteAtomic(manifestPath, manifest.Write)
}

func listDependencies(ctx context.Context, product string) (string, error) {
	// Go can update go.sum in readonly mode. Give it disposable module files
	// while resolving packages from the actual product checkout.
	dir, err := os.MkdirTemp("", "factory-golist-*")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(dir)
	for _, name := range []string{"go.mod", "go.sum"} {
		err := copyFile(filepath.Join(product, name), filepath.Join(dir, name))
		if err != nil && !(name == "go.sum" && errors.Is(err, os.ErrNotExist)) {
			return "", err
		}
	}
	cmd := exec.CommandContext(ctx, "go", "list", "-deps", "-f", "{{with .Module}}{{.Path}} {{.Version}}{{end}}",
		"-modfile="+filepath.Join(dir, "go.mod"), "./...")
	cmd.Dir = product
	cmd.Env = append(cmd.Environ(), "GOTOOLCHAIN=local", "GOFLAGS=-mod=readonly",
		"GOPROXY="+publicProxy, "GOVCS=*:off", "GOWORK=off", "GOENV=off", "GOPRIVATE=", "GONOPROXY=")
	return commandOutput(cmd)
}

func commandOutput(cmd *exec.Cmd) (string, error) {
	output, err := cmd.Output()
	if err != nil {
		if exit, ok := errors.AsType[*exec.ExitError](err); ok && len(exit.Stderr) != 0 {
			return "", fmt.Errorf("%s %s: %w: %s", filepath.Base(cmd.Path), cmd.Args[1], err, strings.TrimSpace(string(exit.Stderr)))
		}
		return "", fmt.Errorf("%s %s: %w", filepath.Base(cmd.Path), cmd.Args[1], err)
	}
	return string(output), nil
}

func copyFile(source, dest string) error {
	f, err := os.Open(source)
	if err != nil {
		return err
	}
	defer f.Close()
	return delivery.WriteAtomic(dest, func(w io.Writer) error {
		_, err := io.Copy(w, f)
		return err
	})
}

func removeIfPresent(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
