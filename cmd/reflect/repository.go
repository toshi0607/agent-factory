package main

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"

	"github.com/toshi0607/agent-factory/internal/patchcheck"
)

const gitConfig = `[core]
	repositoryformatversion = 0
	filemode = true
	protectHFS = true
	protectNTFS = true
	splitIndex = false
	untrackedCache = false
[gc]
	auto = 0
[maintenance]
	auto = false
[submodule]
	recurse = false
`

var (
	objectID = regexp.MustCompile(`^[0-9a-f]{40}$`)
	workID   = regexp.MustCompile(`^p0-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}$`)
)

type repository struct {
	product, metadata, common, scratch string
}

func openRepository(product string) (*repository, *failure) {
	product, err := filepath.Abs(product)
	if err != nil {
		return nil, failed("cannot resolve product checkout")
	}
	metadata := filepath.Join(product, ".git")
	for _, name := range []string{metadata, filepath.Join(metadata, "objects"), filepath.Join(metadata, "refs")} {
		info, err := os.Lstat(name)
		if err != nil || !info.IsDir() {
			return nil, failed("product must have a local Git directory with objects and refs")
		}
	}
	for _, entry := range []struct {
		name     string
		dir      bool
		required bool
	}{
		{"HEAD", false, true}, {"index", false, false}, {"packed-refs", false, false},
		{"shallow", false, false}, {"objects/info", true, false}, {"objects/pack", true, false},
		{"logs", true, false}, {"logs/HEAD", false, false},
	} {
		info, err := os.Lstat(filepath.Join(metadata, entry.name))
		if errors.Is(err, os.ErrNotExist) && !entry.required {
			continue
		}
		if err != nil || (entry.dir && !info.IsDir()) || (!entry.dir && !info.Mode().IsRegular()) {
			return nil, failed("unsafe product Git metadata")
		}
		if entry.name == "logs/HEAD" {
			// Git appends to this file when it detaches HEAD.
			if stat, ok := info.Sys().(*syscall.Stat_t); !ok || stat.Nlink != 1 {
				return nil, failed("unsafe product HEAD reflog")
			}
		}
	}
	for _, name := range []string{"objects/info/alternates", "objects/info/http-alternates"} {
		if _, err := os.Lstat(filepath.Join(metadata, name)); !errors.Is(err, os.ErrNotExist) {
			return nil, failed("product Git object alternates are unsupported")
		}
	}

	scratch, err := os.MkdirTemp("", "reflect-*")
	if err != nil {
		return nil, failed("cannot create temporary repository")
	}
	repo := &repository{product: product, metadata: metadata, common: filepath.Join(scratch, "common"), scratch: scratch}
	if err := repo.isolateConfig(); err != nil {
		repo.close()
		return nil, failed("cannot isolate product Git configuration")
	}
	return repo, nil
}

// Git uses the isolated common directory for config, attributes and hooks.
// Only the object store and the refs needed to resolve HEAD are shared.
func (r *repository) isolateConfig() error {
	if err := os.Mkdir(r.common, 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(r.common, "config"), []byte(gitConfig), 0o600); err != nil {
		return err
	}
	for _, name := range []string{"objects", "refs", "packed-refs", "shallow"} {
		source := filepath.Join(r.metadata, name)
		if _, err := os.Lstat(source); errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			return err
		}
		if err := os.Symlink(source, filepath.Join(r.common, name)); err != nil {
			return err
		}
	}
	return nil
}

func (r *repository) close() { _ = os.RemoveAll(r.scratch) }

func (r *repository) git(input []byte, args ...string) ([]byte, error) {
	return r.gitWithIndex("", input, args...)
}

func (r *repository) gitWithIndex(index string, input []byte, args ...string) ([]byte, error) {
	env := []string{
		"GIT_DIR=" + r.metadata, "GIT_COMMON_DIR=" + r.common, "GIT_WORK_TREE=" + r.product,
		"GIT_OPTIONAL_LOCKS=0", "GIT_ALLOW_PROTOCOL=",
	}
	if index != "" {
		env = append(env, "GIT_INDEX_FILE="+index)
	}
	return patchcheck.GitWithEnv(r.product, input, env, args...)
}

func (r *repository) checkBase(base string) *failure {
	head, err := r.git(nil, "rev-parse", "--verify", "HEAD^{commit}")
	if err != nil {
		return failed("cannot resolve product HEAD")
	}
	if strings.TrimSpace(string(head)) != base {
		return reject("base commit does not equal product HEAD")
	}
	tree, err := r.git(nil, "ls-tree", "-rz", "--full-tree", base)
	if err != nil {
		return failed("cannot list base tree")
	}
	if problem := r.checkAttributes(tree); problem != nil {
		return problem
	}
	return r.checkClean(base, tree)
}

func (r *repository) checkAttributes(tree []byte) *failure {
	for entry := range bytes.SplitSeq(tree, []byte{0}) {
		header, name, _ := bytes.Cut(entry, []byte{'\t'})
		if path.Base(string(name)) != ".gitattributes" {
			continue
		}
		fields := bytes.Fields(header)
		if len(fields) != 3 || !bytes.Equal(fields[1], []byte("blob")) {
			continue
		}
		// Read the base blob directly, before any command uses worktree attributes.
		blob, err := r.git(nil, "cat-file", "blob", string(fields[2]))
		if err != nil {
			return failed("cannot read base .gitattributes")
		}
		if hasFilterAttribute(string(blob)) {
			return rejectPath("base .gitattributes contains filter=", string(name))
		}
	}
	return nil
}

func hasFilterAttribute(blob string) bool {
	for line := range strings.SplitSeq(blob, "\n") {
		line = strings.TrimLeft(line, " \t\r")
		if line == "" || line[0] == '#' {
			continue
		}
		// A quoted pattern may itself contain "filter=" or whitespace.
		if line[0] == '"' {
			if pattern, err := strconv.QuotedPrefix(line); err == nil {
				line = line[len(pattern):]
			} else if end := strings.IndexAny(line, " \t\r"); end >= 0 {
				line = line[end:]
			} else {
				continue
			}
		} else if end := strings.IndexAny(line, " \t\r"); end >= 0 {
			line = line[end:]
		} else {
			continue
		}
		for field := range strings.FieldsSeq(line) {
			if strings.HasPrefix(field, "filter=") {
				return true
			}
		}
	}
	return false
}

func (r *repository) checkClean(base string, tree []byte) *failure {
	// Submodule status can enter an untrusted nested Git repository.
	for entry := range bytes.SplitSeq(tree, []byte{0}) {
		if !bytes.HasPrefix(entry, []byte("160000 ")) {
			continue
		}
		_, name, _ := bytes.Cut(entry, []byte{'\t'})
		if !canonicalPath(string(name)) {
			return rejectPath("unsafe base gitlink path", string(name))
		}
		dir := filepath.Join(r.product, string(name))
		info, err := os.Lstat(dir)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil || !info.IsDir() {
			return rejectPath("dirty product worktree at gitlink", string(name))
		}
		children, err := os.ReadDir(dir)
		if err != nil || len(children) != 0 {
			return rejectPath("populated submodule in product worktree", string(name))
		}
	}
	if _, err := r.git(nil, "diff-index", "--cached", "--quiet", "--ignore-submodules=none",
		"--no-ext-diff", "--no-textconv", base, "--"); err != nil {
		if exit, ok := errors.AsType[*exec.ExitError](err); ok && exit.ExitCode() == 1 {
			return reject("dirty product index")
		}
		return failed("cannot check product index")
	}
	// Use a fresh base index so cached stat data cannot hide worktree changes.
	index := filepath.Join(r.scratch, "base-index")
	if _, err := r.gitWithIndex(index, nil, "read-tree", base); err != nil {
		return failed("cannot read base into temporary index")
	}
	status, err := r.gitWithIndex(index, nil, "status", "--porcelain", "--untracked-files=all", "--ignore-submodules=all")
	if err != nil {
		return failed("cannot check product against base files")
	}
	if len(status) != 0 {
		return reject("dirty product worktree")
	}
	flags, err := r.git(nil, "ls-files", "-v", "-z")
	if err != nil {
		return failed("cannot read product index flags")
	}
	for entry := range bytes.SplitSeq(flags, []byte{0}) {
		// Lowercase denotes assume-unchanged, and S denotes skip-worktree.
		if len(entry) > 2 && (entry[0] == 'S' || entry[0] >= 'a' && entry[0] <= 'z') {
			return rejectPath("unsupported product index flag for", string(entry[2:]))
		}
	}
	return nil
}

func (r *repository) clone() (string, *failure) {
	dir := filepath.Join(r.scratch, "tree")
	if _, err := patchcheck.Git(r.scratch, nil, "init", "--template=", "--", dir); err != nil {
		return "", failed("cannot initialize local clone")
	}
	gitDir := filepath.Join(dir, ".git")
	if err := os.WriteFile(filepath.Join(gitDir, "config"), []byte(gitConfig), 0o600); err != nil {
		return "", failed("cannot configure local clone")
	}
	// Borrow base objects locally. The clone has its own index, refs, and writes.
	if err := os.WriteFile(filepath.Join(gitDir, "objects", "info", "alternates"),
		[]byte(strconv.Quote(filepath.Join(r.metadata, "objects"))+"\n"), 0o600); err != nil {
		return "", failed("cannot link base objects into local clone")
	}
	if _, err := os.Lstat(filepath.Join(r.common, "shallow")); err == nil {
		if err := os.Symlink(filepath.Join(r.common, "shallow"), filepath.Join(gitDir, "shallow")); err != nil {
			return "", failed("cannot link shallow boundary into local clone")
		}
	}
	return dir, nil
}

func canonicalPath(name string) bool {
	return name != "." && filepath.IsLocal(name) && path.Clean(name) == name
}
