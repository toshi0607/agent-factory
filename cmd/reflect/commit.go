package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/toshi0607/agent-factory/internal/patchcheck"
	"github.com/toshi0607/agent-factory/judge/google-cloud-emulator/p0"
)

type commitResult struct {
	Commit    string `json:"commit"`
	Tree      string `json:"tree"`
	Parent    string `json:"parent"`
	TargetRef string `json:"target_ref"`
}

func commit(opt options) *failure {
	data, problem := readLimited(opt.decision, "decision", maxDecisionSize)
	if problem != nil {
		return problem
	}
	var d decision
	if err := decodeJSON(data, &d); err != nil {
		return reject("invalid decision JSON")
	}
	if !d.Accepted {
		return reject("decision is not accepted")
	}
	p, hash, problem := readPolicy(opt.policy)
	if problem != nil {
		return problem
	}
	if hash != d.PolicySHA256 {
		return reject("decision policy hash mismatch")
	}
	patches, problem := readPatches(opt)
	if problem != nil {
		return problem
	}
	if patches.roleHash != d.PatchSHA256 || (patches.generatedHash == nil) != (d.GenPatchSHA256 == nil) ||
		(patches.generatedHash != nil && *patches.generatedHash != *d.GenPatchSHA256) {
		return reject("decision patch hash mismatch")
	}
	if !objectID.MatchString(d.BaseCommit) || !objectID.MatchString(d.TreeSHA) {
		return reject("invalid decision base or tree id")
	}
	if !objectID.MatchString(opt.factoryCommit) || !workID.MatchString(d.WorkID) {
		return reject("invalid factory commit or work id")
	}
	repo, problem := openRepository(opt.product)
	if problem != nil {
		return problem
	}
	defer repo.close()
	if problem := repo.checkBase(d.BaseCommit); problem != nil {
		return problem
	}
	if !p.TargetRefAllowed(opt.targetRef) {
		return reject("target ref is not allowed")
	}
	if problem := checkRole(p, d.Role); problem != nil {
		return problem
	}
	task, ok := p0.Lookup(d.Task)
	if !ok {
		return reject("unknown decision P0 task")
	}
	wantTree := d.TreeSHA
	clone, problem := repo.inspect(p, task, patches, opt.allowDependencies, &d)
	if problem != nil {
		return problem
	}
	if d.TreeSHA != wantTree {
		return reject("decision tree mismatch")
	}

	id, err := createCommit(clone, d.TreeSHA, d.BaseCommit, commitMessage(d, opt.factoryCommit))
	if err != nil {
		return failed("cannot create reflected commit")
	}
	pack, err := patchcheck.Git(clone, []byte(id+"\n^"+d.BaseCommit+"\n"), "pack-objects", "--stdout", "--revs")
	if err != nil {
		return failed("cannot pack reflected commit")
	}
	if dir, err := os.Stat(filepath.Dir(opt.out)); err != nil || !dir.IsDir() {
		return failed("invalid commit result directory")
	}
	if dest, err := os.Lstat(opt.out); err == nil && dest.IsDir() {
		return failed("commit result destination is a directory")
	}
	if _, err := repo.git(pack, "index-pack", "--stdin"); err != nil {
		return failed("cannot import reflected commit")
	}
	if problem := repo.checkBase(d.BaseCommit); problem != nil {
		return problem
	}
	if _, err := repo.git(nil, "checkout", "--detach", "--no-overwrite-ignore", id); err != nil {
		return failed("cannot check out reflected commit")
	}
	if err := writeJSON(opt.out, commitResult{Commit: id, Tree: d.TreeSHA, Parent: d.BaseCommit, TargetRef: opt.targetRef}); err != nil {
		return failed("cannot write commit result")
	}
	return nil
}

func createCommit(dir, tree, parent, message string) (string, error) {
	out, err := patchcheck.Git(dir, []byte(message),
		"-c", "user.name=agent-factory", "-c", "user.email=agent-factory@users.noreply.github.com",
		"commit-tree", "--no-gpg-sign", tree, "-p", parent, "-F", "-")
	if err != nil {
		return "", err
	}
	id := strings.TrimSpace(string(out))
	if !objectID.MatchString(id) {
		return "", errors.New("git returned an invalid commit id")
	}
	return id, nil
}

func commitMessage(d decision, factoryCommit string) string {
	var message strings.Builder
	fmt.Fprintf(&message, "factory(%s): %s\n\n", d.Role, d.Task)
	fmt.Fprintf(&message, "Factory-Work-Id: %s\n", d.WorkID)
	fmt.Fprintf(&message, "Factory-Role: %s\n", d.Role)
	fmt.Fprintf(&message, "Factory-Task: %s\n", d.Task)
	fmt.Fprintf(&message, "Factory-Base-Commit: %s\n", d.BaseCommit)
	fmt.Fprintf(&message, "Factory-Patch-Sha256: %s\n", d.PatchSHA256)
	if d.GenPatchSHA256 != nil {
		fmt.Fprintf(&message, "Factory-Gen-Patch-Sha256: %s\n", *d.GenPatchSHA256)
	}
	fmt.Fprintf(&message, "Factory-Policy-Sha256: %s\n", d.PolicySHA256)
	fmt.Fprintf(&message, "Factory-Commit: %s\n", factoryCommit)
	return message.String()
}
