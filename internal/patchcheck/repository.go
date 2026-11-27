package patchcheck

import (
	"errors"
	"os"
	"path/filepath"
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

// ConfigureRepository installs the known config in a repository owned by the caller.
func ConfigureRepository(gitDir string) error {
	return os.WriteFile(filepath.Join(gitDir, "config"), []byte(gitConfig), 0o600)
}

// WorkTreeEnv binds Git to explicit metadata and worktree directories.
func WorkTreeEnv(gitDir, workTree string) []string {
	return []string{"GIT_DIR=" + gitDir, "GIT_WORK_TREE=" + workTree, "GIT_OPTIONAL_LOCKS=0"}
}

// IsolateCommonDir makes Git use the isolated common directory for config, attributes and hooks.
// Only the object store and the refs needed to resolve HEAD are shared.
func IsolateCommonDir(metadata, common string) error {
	if err := os.Mkdir(common, 0o700); err != nil {
		return err
	}
	if err := ConfigureRepository(common); err != nil {
		return err
	}
	for _, name := range []string{"objects", "refs", "packed-refs", "shallow"} {
		source := filepath.Join(metadata, name)
		if _, err := os.Lstat(source); errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			return err
		}
		if err := os.Symlink(source, filepath.Join(common, name)); err != nil {
			return err
		}
	}
	return nil
}
