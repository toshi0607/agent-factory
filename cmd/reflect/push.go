package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/toshi0607/agent-factory/internal/patchcheck"
)

const githubAuthKey = "http.https://github.com/.extraheader"

var (
	githubRepository = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)
	gitSecrets       = regexp.MustCompile(`(?i)AUTHORIZATION:[^\r\n]*|x-access-token:[^@\s]*|[A-Za-z0-9+/_-]{41,}={0,2}`)
	// Only push_test.go enables the local transport.
	allowLocalRemoteForTest bool
)

type pushResult struct {
	Pushed    bool   `json:"pushed"`
	Commit    string `json:"commit"`
	TargetRef string `json:"target_ref"`
	Previous  string `json:"previous"`
}

func push(opt options) *failure {
	p, _, problem := readPolicy(opt.policy)
	if problem != nil {
		return problem
	}
	if !p.TargetRefAllowed(opt.targetRef) {
		return reject("target ref is not allowed")
	}
	protocol := "https"
	if allowLocalRemoteForTest && filepath.IsAbs(opt.remote) && !strings.ContainsRune(opt.remote, 0) {
		protocol = "file"
	} else if !githubRepository.MatchString(p.Product.Repository) ||
		opt.remote != "https://github.com/"+p.Product.Repository+".git" {
		return reject("remote is not allowed")
	}

	data, problem := readLimited(opt.result, "commit result", maxJudgeSize)
	if problem != nil {
		return problem
	}
	var result commitResult
	if err := decodeJSON(data, &result); err != nil {
		return reject("invalid commit result JSON")
	}
	if result.TargetRef != opt.targetRef {
		return reject("commit result target ref mismatch")
	}
	if !objectID.MatchString(result.Commit) || !objectID.MatchString(result.Tree) || !objectID.MatchString(result.Parent) {
		return reject("invalid commit result object id")
	}

	repo, problem := openRepository(opt.product)
	if problem != nil {
		return problem
	}
	defer repo.close()
	if problem := repo.checkPushCommit(result); problem != nil {
		return problem
	}

	env := append(repo.gitEnv(), "GIT_ALLOW_PROTOCOL="+protocol, "GIT_ASKPASS=/bin/false")
	// The private repository requires the same header for discovery and push.
	if protocol == "https" {
		auth, problem := githubAuthEnv(os.Environ())
		if problem != nil {
			return problem
		}
		env = append(env, auth...)
	}
	remoteGit := func(args ...string) ([]byte, error) {
		config := []string{"-c", "credential.helper=", "-c", "http.followRedirects=false"}
		return patchcheck.GitWithEnv(repo.scratch, nil, env, append(config, args...)...)
	}
	head, err := remoteGit("ls-remote", "--symref", "--", opt.remote, "HEAD")
	if err != nil {
		return remoteFailure("cannot read remote default branch", err)
	}
	if !p.Reflect.DefaultBranchAllowed {
		defaultRef := remoteDefaultBranch(string(head))
		switch defaultRef {
		case "":
			return failed("cannot determine remote default branch")
		case opt.targetRef:
			return reject("target ref is the default branch")
		}
	}
	refs, err := remoteGit("ls-remote", "--refs", "--", opt.remote, opt.targetRef)
	if err != nil {
		return remoteFailure("cannot read target ref", err)
	}
	previous := ""
	for line := range strings.SplitSeq(string(refs), "\n") {
		if line == "" {
			continue
		}
		id, ref, ok := strings.Cut(line, "\t")
		if !ok || !objectID.MatchString(id) {
			return failed("invalid Git remote ref output")
		}
		if ref == opt.targetRef {
			previous = id
		}
	}
	if previous != "" && previous != result.Parent {
		return reject("target ref moved")
	}

	output, err := remoteGit("push", "--atomic", "--no-verify", "--porcelain",
		"--force-with-lease="+opt.targetRef+":"+previous, "--", opt.remote, result.Commit+":"+opt.targetRef)
	if err != nil {
		for line := range strings.SplitSeq(string(output), "\n") {
			if strings.HasPrefix(line, "!\t") && strings.HasSuffix(line, "\t[rejected] (stale info)") {
				return reject("target ref moved")
			}
		}
		return remoteFailure("cannot push reflected commit", err)
	}
	// Git considers a concurrent update to the same commit already up to date.
	for line := range strings.SplitSeq(string(output), "\n") {
		if strings.HasPrefix(line, "=\t") {
			return reject("target ref moved")
		}
	}
	if err := writeJSON(opt.out, pushResult{
		Pushed: true, Commit: result.Commit, TargetRef: opt.targetRef, Previous: previous,
	}); err != nil {
		return failed("pushed reflected commit but cannot write push result")
	}
	return nil
}

func githubAuthEnv(env []string) ([]string, *failure) {
	var auth []string
	seen := make(map[string]bool, 3)
	for _, entry := range env {
		key, value, _ := strings.Cut(entry, "=")
		if key != "GIT_CONFIG" && !strings.HasPrefix(key, "GIT_CONFIG_") {
			continue
		}
		if seen[key] {
			return nil, failed("invalid Git authentication configuration")
		}
		seen[key] = true
		switch {
		case key == "GIT_CONFIG_COUNT" && value == "1",
			key == "GIT_CONFIG_KEY_0" && value == githubAuthKey,
			key == "GIT_CONFIG_VALUE_0" && value != "":
			auth = append(auth, entry)
		default:
			return nil, failed("invalid Git authentication configuration")
		}
	}
	if len(auth) != 0 && len(auth) != 3 {
		return nil, failed("invalid Git authentication configuration")
	}
	return auth, nil
}

func remoteDefaultBranch(output string) string {
	for line := range strings.SplitSeq(output, "\n") {
		target, ref, _ := strings.Cut(line, "\t")
		if branch, ok := strings.CutPrefix(target, "ref: refs/heads/"); ok && branch != "" && ref == "HEAD" {
			return "refs/heads/" + branch
		}
	}
	return ""
}

func (r *repository) checkPushCommit(result commitResult) *failure {
	kind, err := r.git([]byte(result.Commit+"\n"), "cat-file", "--batch-check=%(objecttype)")
	if err != nil {
		return failed("cannot check commit result object")
	}
	if string(kind) != "commit\n" {
		return reject("commit result does not name a product commit")
	}
	raw, err := r.git(nil, "cat-file", "commit", result.Commit)
	if err != nil {
		return failed("cannot read commit result object")
	}
	header, message, ok := strings.Cut(string(raw), "\n\n")
	tree, parents := "", []string{}
	for line := range strings.SplitSeq(header, "\n") {
		if id, found := strings.CutPrefix(line, "tree "); found {
			tree = id
		}
		if id, found := strings.CutPrefix(line, "parent "); found {
			parents = append(parents, id)
		}
	}
	if !ok || tree != result.Tree {
		return reject("commit result tree mismatch")
	}
	if len(parents) != 1 || parents[0] != result.Parent {
		return reject("commit result parent mismatch")
	}
	trailers, err := r.git([]byte(message), "interpret-trailers", "--parse")
	if err != nil {
		return failed("cannot parse commit trailers")
	}
	for line := range strings.SplitSeq(string(trailers), "\n") {
		key, value, found := strings.Cut(line, ":")
		if found && strings.EqualFold(key, "Factory-Work-Id") && workID.MatchString(strings.TrimSpace(value)) {
			return nil
		}
	}
	return reject("commit is missing a valid Factory-Work-Id trailer")
}

func sanitizeGitError(message string) string {
	return gitSecrets.ReplaceAllString(message, "[redacted]")
}

func remoteFailure(reason string, err error) *failure {
	// Quote Git diagnostics so embedded newlines cannot become runner commands.
	return failed(fmt.Sprintf("%s: %q", reason, sanitizeGitError(err.Error())))
}
