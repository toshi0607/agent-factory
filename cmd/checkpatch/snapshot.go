package main

import (
	"crypto/sha256"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/toshi0607/agent-factory/internal/delivery"
	"github.com/toshi0607/agent-factory/internal/patchcheck"
	"github.com/toshi0607/agent-factory/poc/record"
)

const maxGeneratedPatchSize = 5 << 20

func configureRepository(repo string) error {
	gitDir := filepath.Join(repo, ".git")
	if err := patchcheck.ConfigureRepository(gitDir); err != nil {
		return fmt.Errorf("isolate repository config: %w", err)
	}
	// These highest-priority attributes keep checkout and staging byte-exact,
	// even when the worktree contains its own .gitattributes.
	info := filepath.Join(gitDir, "info")
	if err := os.MkdirAll(info, 0o755); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(info, "attributes"),
		[]byte("* -text -eol -crlf -ident -filter -working-tree-encoding\n"), 0o600)
}

func stageTree(tree string, env []string) (string, error) {
	if err := filepath.WalkDir(tree, func(name string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := os.Lstat(name)
		if err != nil {
			return err
		}
		if strings.EqualFold(info.Name(), ".git") {
			return fmt.Errorf("worktree contains a .git entry at %q", name)
		}
		if !info.IsDir() && (name == tree || !info.Mode().IsRegular()) {
			return fmt.Errorf("worktree path %q is not a regular file or directory", name)
		}
		return nil
	}); err != nil {
		return "", fmt.Errorf("scan worktree: %w", err)
	}
	// A fresh index forces Git to read every file even if stat data matches the
	// earlier snapshot. Include ignored files because the build can see them.
	if _, err := patchcheck.GitWithEnv(tree, nil, env, "read-tree", "--empty"); err != nil {
		return "", err
	}
	if _, err := patchcheck.GitWithEnv(tree, nil, env, "add", "-f", "-A", "--"); err != nil {
		return "", err
	}
	id, err := patchcheck.GitWithEnv(tree, nil, env, "write-tree")
	return strings.TrimSpace(string(id)), err
}

func snapshotGeneration(work, tree string, env []string, out *record.CheckResult) error {
	judgedTree, err := stageTree(tree, env)
	if err != nil {
		return err
	}
	diff := []string{"diff", "--cached", "--no-ext-diff", "--no-textconv", "--no-renames"}
	patch, err := patchcheck.GitWithEnvLimit(tree, env, maxGeneratedPatchSize,
		append(slices.Clone(diff), "--binary", "HEAD", "--")...)
	if err != nil {
		return fmt.Errorf("generate patch: %w", err)
	}
	if len(patch) != 0 {
		names, err := patchcheck.GitWithEnv(tree, nil, env, append(diff, "--name-only", "-z", "HEAD", "--")...)
		if err != nil {
			return fmt.Errorf("list generated paths: %w", err)
		}
		paths := strings.Split(strings.TrimSuffix(string(names), "\x00"), "\x00")
		slices.Sort(paths)
		if err := delivery.WriteAtomic(filepath.Join(work, "gen-patch.diff"), func(w io.Writer) error {
			_, err := w.Write(patch)
			return err
		}); err != nil {
			return fmt.Errorf("write generated patch artifact: %w", err)
		}
		out.GenPatchSHA256 = fmt.Sprintf("%x", sha256.Sum256(patch))
		out.GenChangedPaths = paths
	}
	out.GenOK = true
	out.JudgedTree = judgedTree
	return nil
}
