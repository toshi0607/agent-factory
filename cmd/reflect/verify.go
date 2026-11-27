package main

import (
	"encoding/json"
	"errors"
	"path"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/toshi0607/agent-factory/internal/patchcheck"
	"github.com/toshi0607/agent-factory/internal/policy"
	"github.com/toshi0607/agent-factory/judge/google-cloud-emulator/p0"
	"github.com/toshi0607/agent-factory/poc/record"
)

type decision struct {
	Accepted       bool     `json:"accepted"`
	Reason         string   `json:"reason"`
	WorkID         string   `json:"work_id"`
	Role           string   `json:"role"`
	Task           string   `json:"task"`
	BaseCommit     string   `json:"base_commit"`
	PatchSHA256    string   `json:"patch_sha256"`
	GenPatchSHA256 *string  `json:"gen_patch_sha256"`
	Paths          []string `json:"paths"`
	GenPaths       []string `json:"gen_paths"`
	PolicySHA256   string   `json:"policy_sha256"`
	TreeSHA        string   `json:"tree_sha"`
	JudgedTree     *string  `json:"judged_tree"`
}

func verify(opt options) *failure {
	d := decision{
		WorkID: opt.workID, Role: opt.role, Task: opt.task, BaseCommit: opt.base,
		Paths: []string{}, GenPaths: []string{},
	}
	problem := verifyPatch(opt, &d)
	d.Accepted = problem == nil
	d.Reason = "verified"
	if problem != nil {
		d.Reason = problem.reason
	}
	if err := writeJSON(opt.out, d); err != nil {
		return failed("cannot write decision")
	}
	return problem
}

func verifyPatch(opt options, d *decision) *failure {
	if !objectID.MatchString(opt.base) {
		return reject("base commit must be 40 lowercase hex characters")
	}
	repo, problem := openRepository(opt.product)
	if problem != nil {
		return problem
	}
	defer repo.close()
	if problem := repo.checkBase(opt.base); problem != nil {
		return problem
	}
	if !workID.MatchString(opt.workID) {
		return reject("invalid work id")
	}
	patches, problem := readPatches(opt)
	d.PatchSHA256, d.GenPatchSHA256 = patches.roleHash, patches.generatedHash
	if problem != nil {
		return problem
	}
	p, hash, problem := readPolicy(opt.policy)
	d.PolicySHA256 = hash
	if problem != nil {
		return problem
	}
	if problem := checkRole(p, opt.role); problem != nil {
		return problem
	}
	if problem := checkJudge(opt.judge, patches, d); problem != nil {
		return problem
	}
	task, ok := p0.Lookup(opt.task)
	if !ok {
		return failed("unknown P0 task")
	}
	if _, problem := repo.inspect(p, task, patches, opt.allowDependencies, d); problem != nil {
		return problem
	}
	return d.checkJudgedTree()
}

func (d *decision) checkJudgedTree() *failure {
	if d.JudgedTree != nil && d.TreeSHA != *d.JudgedTree {
		return reject("judged tree mismatch")
	}
	return nil
}

func checkRole(p policy.Policy, role string) *failure {
	if len(p.Roles[role].Write) == 0 {
		return failed("role does not exist or has no write patterns")
	}
	if strings.ContainsFunc(role, func(r rune) bool { return unicode.IsControl(r) || r == '\u2028' || r == '\u2029' }) {
		return failed("role must be a single line")
	}
	return nil
}

func checkJudge(name string, patches patchData, d *decision) *failure {
	data, problem := readLimited(name, "judge result", maxJudgeSize)
	if problem != nil {
		return problem
	}
	var judge struct {
		record.CheckResult
		GenPatchSHA256 json.RawMessage `json:"gen_patch_sha256"`
	}
	if err := decodeJSON(data, &judge); err != nil {
		return reject("invalid judge result JSON")
	}
	if judge.Task != d.Task {
		return reject("judge task mismatch")
	}
	if judge.PatchSHA256 != patches.roleHash {
		return reject("judge patch hash mismatch")
	}
	for _, check := range []struct {
		name string
		ok   bool
	}{
		{"paths_ok", judge.PathsOK}, {"apply_ok", judge.ApplyOK}, {"gen_ok", judge.GenOK},
		{"build_ok", judge.BuildOK}, {"check_passed", judge.CheckPassed},
	} {
		if !check.ok {
			return reject("judge failed check: " + check.name)
		}
	}
	if len(judge.Failures) != 0 || judge.Error != "" {
		return reject("judge result reports failures or an error")
	}
	if judge.JudgedTree != "" {
		d.JudgedTree = new(judge.JudgedTree)
	} else if patches.generatedHash != nil || judge.GenPatchSHA256 != nil {
		return reject("judge result lacks a judged tree")
	}
	if patches.generatedHash == nil {
		if judge.GenPatchSHA256 != nil || len(judge.GenChangedPaths) != 0 {
			return reject("judge result requires a generated patch")
		}
		return nil
	}
	if judge.GenPatchSHA256 == nil {
		return reject("judge result lacks a generated patch hash")
	}
	var hash string
	if err := json.Unmarshal(judge.GenPatchSHA256, &hash); err != nil || hash != *patches.generatedHash {
		return reject("judge generated patch hash mismatch")
	}
	return nil
}

func (r *repository) inspect(p policy.Policy, task p0.Task, patches patchData, allowDependencies bool, d *decision) (string, *failure) {
	clone, problem := r.clone()
	if problem != nil {
		return "", problem
	}
	roleAllowed := func(name string) string {
		switch {
		case p.Protected(name):
			return "protected path"
		case p.DependencyFile(name):
			return "dependency file in role patch"
		case p.Generated(name):
			return "generated path in role patch"
		case !p.RoleMayWrite(d.Role, name):
			return "path outside role's writable paths"
		case !p0.PathAllowed(task, name):
			return "path outside task's writable paths"
		}
		return ""
	}

	rolePaths, problem := inspectPatch(clone, d.BaseCommit, patches.role, roleAllowed)
	if problem != nil {
		return "", problem
	}
	d.Paths = rolePaths
	if _, err := patchcheck.Git(clone, nil, "checkout", "--detach", d.BaseCommit); err != nil {
		return "", failed("cannot check out base in local clone")
	}
	roleTree, problem := applyPatch(clone, d.BaseCommit, "role", patches.role, rolePaths)
	if problem != nil {
		return "", problem
	}
	if patches.generatedHash == nil {
		d.TreeSHA = roleTree
		return clone, nil
	}

	roleCommit, err := createCommit(clone, roleTree, d.BaseCommit, "Apply role patch for inspection\n")
	if err != nil {
		return "", failed("cannot record role tree in local clone")
	}
	generatedAllowed := func(name string) string {
		switch {
		case p.Protected(name):
			return "protected path"
		case slices.Contains(rolePaths, name):
			return "path appears in both patches"
		case p.DependencyFile(name):
			if !allowDependencies {
				return "dependency file requires -allow-dependency-changes"
			}
		case !p.Generated(name):
			return "path outside generated paths"
		}
		return ""
	}

	genPaths, problem := inspectPatch(clone, roleCommit, patches.generated, generatedAllowed)
	if problem != nil {
		return "", problem
	}
	d.GenPaths = genPaths
	tree, problem := applyPatch(clone, roleCommit, "generated", patches.generated, genPaths)
	if problem != nil {
		return "", problem
	}
	d.TreeSHA = tree
	return clone, nil
}

func inspectPatch(dir, base string, patch []byte, category func(string) string) ([]string, *failure) {
	var denied *failure
	paths, code, err := patchcheck.Inspect(dir, base, patch, func(name string) bool {
		switch {
		case !canonicalPath(name) || !utf8.ValidString(name) || path.Base(name) == ".git":
			denied = rejectPath("unsafe patch path", name)
		default:
			if reason := category(name); reason != "" {
				denied = rejectPath(reason, name)
			}
		}
		return denied == nil
	})
	switch {
	case err == nil:
		return paths, nil
	case denied != nil:
		return nil, denied
	case code == 2:
		return nil, failed("cannot inspect patch")
	}
	if rejection, ok := errors.AsType[*patchcheck.Rejection](err); ok {
		if rejection.Path != "" {
			return nil, rejectPath(rejection.Category, rejection.Path)
		}
		return nil, reject(rejection.Category)
	}
	return nil, reject("invalid or empty patch")
}

func applyPatch(dir, base, label string, patch []byte, paths []string) (string, *failure) {
	if _, err := patchcheck.Git(dir, patch, "apply", "--index", "--"); err != nil {
		if patchcheck.GitRejectionCode(err) == 1 {
			return "", reject(label + " patch does not apply cleanly")
		}
		return "", failed("cannot apply " + label + " patch")
	}
	id, err := patchcheck.Git(dir, nil, "write-tree")
	tree := strings.TrimSpace(string(id))
	if err != nil || !objectID.MatchString(tree) {
		return "", failed("cannot write " + label + " tree")
	}
	// Verify the actual tree delta as well as Git's interpretation of patch headers.
	delta, err := patchcheck.Git(dir, nil, "diff-tree", "-r", "--no-commit-id", "--raw",
		"--no-renames", "--no-ext-diff", "--no-textconv", "-z", base, tree, "--")
	if err != nil {
		return "", failed("cannot inspect " + label + " tree delta")
	}
	if problem := checkDelta(string(delta), paths, label); problem != nil {
		return "", problem
	}
	return tree, nil
}

func checkDelta(delta string, paths []string, label string) *failure {
	for delta != "" {
		header, rest, _ := strings.Cut(delta, "\x00")
		name, next, ok := strings.Cut(rest, "\x00")
		oldMode, fields, _ := strings.Cut(strings.TrimPrefix(header, ":"), " ")
		newMode, _, _ := strings.Cut(fields, " ")
		if !ok || name == "" {
			return failed("invalid Git tree delta")
		}
		if _, found := slices.BinarySearch(paths, name); !found {
			return rejectPath("unexpected path in "+label+" tree", name)
		}
		if !regularOrAbsent(oldMode) || !regularOrAbsent(newMode) {
			return rejectPath("special file mode in "+label+" tree", name)
		}
		if oldMode != "000000" && newMode != "000000" && oldMode != newMode {
			return rejectPath("mode change in "+label+" tree", name)
		}
		delta = next
	}
	return nil
}

func regularOrAbsent(mode string) bool {
	return mode == "000000" || mode == "100644" || mode == "100755"
}
