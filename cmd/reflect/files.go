package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"

	"github.com/toshi0607/agent-factory/internal/delivery"
	"github.com/toshi0607/agent-factory/internal/policy"
)

const (
	maxPatchSize = 5 << 20
	maxJudgeSize = 1 << 20
	// A decision can contain paths from both patches, escaped as JSON strings.
	maxDecisionSize = 12 * maxPatchSize
)

type failure struct {
	code   int
	reason string
}

func reject(reason string) *failure { return &failure{code: 1, reason: reason} }
func failed(reason string) *failure { return &failure{code: 2, reason: reason} }

func rejectPath(category, name string) *failure {
	return reject(fmt.Sprintf("%s %q", category, name[:min(len(name), 200)]))
}

type patchData struct {
	role, generated []byte
	roleHash        string
	generatedHash   *string
}

func readPatches(opt options) (patchData, *failure) {
	var patches patchData
	var problem *failure
	patches.role, problem = readLimited(opt.patch, "role patch", maxPatchSize)
	if problem != nil {
		return patches, problem
	}
	patches.roleHash = digest(patches.role)
	if opt.genPatch == "" {
		return patches, nil
	}
	patches.generated, problem = readLimited(opt.genPatch, "generated patch", maxPatchSize)
	if problem != nil {
		return patches, problem
	}
	patches.generatedHash = new(digest(patches.generated))
	return patches, nil
}

func readLimited(name, label string, limit int64) ([]byte, *failure) {
	info, err := os.Lstat(name)
	if err != nil {
		return nil, failed("cannot stat " + label)
	}
	if !info.Mode().IsRegular() {
		return nil, reject(label + " must be a regular file")
	}
	// Do not follow a symlink or block on a FIFO swapped in after Lstat.
	file, err := os.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, failed("cannot open " + label)
	}
	defer file.Close()
	info, err = file.Stat()
	if err != nil {
		return nil, failed("cannot stat open " + label)
	}
	if !info.Mode().IsRegular() {
		return nil, reject(label + " must be a regular file")
	}
	if info.Size() > limit {
		return nil, reject(label + " exceeds size limit")
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, failed("cannot read " + label)
	}
	if int64(len(data)) > limit {
		return nil, reject(label + " exceeds size limit")
	}
	return data, nil
}

func decodeJSON(data []byte, result any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(result); err != nil {
		return err
	}
	var trailing json.RawMessage
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("expected one JSON record")
	}
	return nil
}

func readPolicy(name string) (policy.Policy, string, *failure) {
	data, err := os.ReadFile(name)
	if err != nil {
		return policy.Policy{}, "", failed("cannot read policy")
	}
	p, err := policy.Decode(bytes.NewReader(data))
	if err != nil {
		return policy.Policy{}, "", failed("invalid policy")
	}
	return p, digest(data), nil
}

func digest(data []byte) string {
	return fmt.Sprintf("%x", sha256.Sum256(data))
}

func writeJSON(name string, artifact any) error {
	return delivery.WriteAtomic(name, func(w io.Writer) error {
		return json.NewEncoder(w).Encode(artifact)
	})
}
