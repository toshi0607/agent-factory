package main

import (
	"bytes"
	"cmp"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"github.com/toshi0607/agent-factory/internal/cfsandbox"
	"github.com/toshi0607/agent-factory/internal/claude"
	"github.com/toshi0607/agent-factory/internal/delivery"
	"github.com/toshi0607/agent-factory/internal/policy"
)

const (
	probeScriptName = "probe.sh"
	maxMinutes      = 45
)

func (r runner) start(ctx context.Context, policyPath, roleName, candidate, files, statePath string, budgetCents, minutes int) (resultErr error) {
	if candidate != "managed-agents" && candidate != workerCandidate {
		return fmt.Errorf("unsupported candidate %q", candidate)
	}
	if err := r.checkNotStopped(ctx); err != nil {
		return err
	}
	if candidate == workerCandidate {
		client, err := r.workerClient()
		if err != nil {
			return err
		}
		r.worker = client
	}
	cfg, err := policy.Load(policyPath)
	if err != nil {
		return err
	}
	role, ok := cfg.Roles[roleName]
	if !ok || role.Agent != "claude" {
		return fmt.Errorf("no Claude role named %q", roleName)
	}
	minutes = cmp.Or(minutes, role.Budget.Minutes)
	if minutes > maxMinutes {
		return fmt.Errorf("time limit %d exceeds the maximum of %d minutes", minutes, maxMinutes)
	}
	if minutes < 1 || minutes > role.Budget.Minutes {
		return fmt.Errorf("-minutes must be positive and no greater than the role's policy limit of %d", role.Budget.Minutes)
	}
	budgetCents = cmp.Or(budgetCents, role.Budget.LLMUSDCents)
	if budgetCents < 1 || budgetCents > role.Budget.LLMUSDCents {
		return fmt.Errorf("-budget-cents must be positive and no greater than the role's policy limit of %d", role.Budget.LLMUSDCents)
	}
	system, err := os.ReadFile(role.Prompt)
	if err != nil {
		return err
	}
	root, err := os.OpenRoot(files)
	if err != nil {
		return err
	}
	defer root.Close()
	manifestData, err := readDeliveryManifest(root)
	if err != nil {
		return err
	}
	manifest, err := parseManifest(manifestData, cfg.Toolchain.Go)
	if err != nil {
		return err
	}
	if probeRole(roleName) && !slices.ContainsFunc(manifest.Files, func(file delivery.File) bool {
		return file.Name == probeScriptName
	}) {
		return errors.New("manifest is missing " + probeScriptName)
	}
	var workerRequest cfsandbox.StartRequest
	if candidate == workerCandidate {
		workerRequest, err = makeWorkerRequest(cfg, role, roleName, string(system), budgetCents, minutes)
		if err != nil {
			return err
		}
	}

	if err := os.MkdirAll(filepath.Dir(statePath), 0o755); err != nil {
		return err
	}
	var suffix [4]byte
	rand.Read(suffix[:])
	workID := fmt.Sprintf("p0-%s-%x", r.clock.Now().UTC().Format("20060102T150405Z"), suffix)
	if candidate == workerCandidate && !cfsandbox.ValidRunID(workID) {
		return errors.New("generated an invalid worker run ID")
	}
	s := state{
		WorkID: workID, Candidate: candidate, Role: roleName, Task: manifest.Task,
		BaseCommit: manifest.BaseCommit, FactoryCommit: os.Getenv("FACTORY_COMMIT"), Model: role.Model,
		BudgetCents: budgetCents, MinutesLimit: minutes,
	}
	if err := writeJSON(statePath, s, delivery.WriteNew); err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("state file already exists: %s", statePath)
		}
		return fmt.Errorf("create state file: %w", err)
	}
	// The state file comes first so that cleanup can end a record whose
	// creation had an unknown outcome. A refusal leaves nothing to clean up.
	if err := r.beginUnit(ctx, s); err != nil {
		if exitCode(err) == exitInProgress {
			err = errors.Join(err, removeOutput(statePath))
		}
		return err
	}
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(resultErr, r.cleanupAfterRun(ctx, s, "", false))
		}
	}()
	if candidate == workerCandidate {
		return r.startWorker(ctx, root, manifest, manifestData, cfg.Toolchain.Go.Filename, workerRequest, s, statePath)
	}

	// Some failed API calls still return an ID for a resource that needs cleanup.
	saveState := func(id string, apiErr error) error {
		if id != "" {
			if err := writeJSON(statePath, s, delivery.WriteAtomic); err != nil {
				return errors.Join(apiErr, fmt.Errorf("update state file: %w", err))
			}
		}
		return apiErr
	}
	s.EnvironmentID, s.EnvironmentRequestSHA256, err = r.api.CreateEnvironment(ctx, workID, allowedHosts(cfg, role))
	if err := saveState(s.EnvironmentID, err); err != nil {
		return fmt.Errorf("create environment: %w", err)
	}
	s.AgentID, s.AgentRequestSHA256, err = r.api.CreateAgent(ctx, workID, role.Model, string(system))
	if err := saveState(s.AgentID, err); err != nil {
		return fmt.Errorf("create agent: %w", err)
	}
	var resources []claude.Resource
	filesByName := make(map[string]string)
	for _, entry := range manifest.Files {
		uploaded, err := r.uploadPrepared(ctx, root, entry)
		if uploaded.ID != "" {
			s.UploadedFileIDs = append(s.UploadedFileIDs, uploaded.ID)
		}
		if err := saveState(uploaded.ID, err); err != nil {
			return fmt.Errorf("upload %s: %w", entry.Name, err)
		}
		filesByName[entry.Name] = uploaded.ID
		resources = append(resources, fileResource(entry.Name, uploaded.ID))
	}
	uploaded, err := r.api.UploadFile(ctx, delivery.ManifestName, bytes.NewReader(manifestData))
	if uploaded.ID != "" {
		s.UploadedFileIDs = append(s.UploadedFileIDs, uploaded.ID)
	}
	if err := saveState(uploaded.ID, err); err != nil {
		return fmt.Errorf("upload manifest: %w", err)
	}
	resources = append(resources, fileResource(delivery.ManifestName, uploaded.ID))

	s.StartedAt = r.clock.Now().UTC()
	created, err := r.api.CreateSession(ctx, s.AgentID, s.EnvironmentID, s.BudgetCents, resources)
	s.SessionID = created.ID
	if err := saveState(s.SessionID, err); err != nil {
		return fmt.Errorf("create session: %w", err)
	}
	if err := r.recordSession(ctx, s); err != nil {
		return err
	}
	message, err := userMessage(created.Resources, filesByName, probeRole(roleName))
	if err != nil {
		return err
	}
	if err := r.api.SendUserMessage(ctx, s.SessionID, message); err != nil {
		return fmt.Errorf("send user message: %w", err)
	}
	return nil
}

// probeRole reports whether a role runs the conditions probe instead of a task.
func probeRole(name string) bool {
	return name == "probe" || strings.HasPrefix(name, "probe-")
}

func allowedHosts(p policy.Policy, role policy.Role) []string {
	hosts := []string{}
	seen := make(map[string]bool)
	for _, rule := range role.Egress {
		for _, host := range p.Egress[rule].AllowedHosts {
			if !seen[host] {
				hosts = append(hosts, host)
				seen[host] = true
			}
		}
	}
	return hosts
}

func readDeliveryManifest(root *os.Root) ([]byte, error) {
	info, err := root.Lstat(delivery.ManifestName)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("manifest.json must be a regular file")
	}
	return root.ReadFile(delivery.ManifestName)
}

func parseManifest(data []byte, goTool policy.Go) (delivery.Manifest, error) {
	var m delivery.Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return m, fmt.Errorf("decode manifest.json: %w", err)
	}
	if strings.TrimSpace(m.Task) == "" || strings.TrimSpace(m.BaseCommit) == "" {
		return m, errors.New("manifest requires a task and base commit")
	}
	required := map[string]bool{
		"setup.sh": false, "finish.sh": false, probeScriptName: false, "task.md": false, "product.tar.gz": false,
		goTool.Filename: false, "modproxy.tar.gz": false,
	}
	for _, item := range m.Files {
		seen, allowed := required[item.Name]
		if !allowed || seen {
			return m, fmt.Errorf("unexpected or duplicate delivery file %q", item.Name)
		}
		if item.Name == goTool.Filename && !strings.EqualFold(item.SHA256, goTool.SHA256) {
			return m, errors.New("manifest toolchain checksum differs from policy")
		}
		required[item.Name] = true
	}
	for name, seen := range required {
		if !seen && name != "modproxy.tar.gz" && name != probeScriptName {
			return m, fmt.Errorf("manifest is missing %s", name)
		}
	}
	return m, nil
}

func (r runner) uploadPrepared(ctx context.Context, root *os.Root, entry delivery.File) (claude.File, error) {
	f, err := openPrepared(root, entry)
	if err != nil {
		return claude.File{}, err
	}
	defer f.Close()
	return r.api.UploadFile(ctx, entry.Name, f)
}

func openPrepared(root *os.Root, entry delivery.File) (*os.File, error) {
	info, err := root.Lstat(entry.Name)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("delivery file must be a regular file")
	}
	f, err := root.Open(entry.Name)
	if err != nil {
		return nil, err
	}
	if err := verifyPrepared(f, entry); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

func verifyPrepared(f *os.File, entry delivery.File) error {
	hash, size, err := delivery.Digest(f)
	if err != nil {
		return err
	}
	if !strings.EqualFold(hash, entry.SHA256) || size != entry.Bytes {
		return errors.New("delivery file checksum or size differs from manifest")
	}
	_, err = f.Seek(0, io.SeekStart)
	return err
}

func fileResource(name, id string) claude.Resource {
	return claude.Resource{Type: "file", FileID: id, MountPath: "/workspace/" + name}
}

func userMessage(resources []claude.Resource, ids map[string]string, probe bool) (string, error) {
	// The response may carry session-scoped file IDs that differ from the
	// uploaded ones, so resources are matched by the requested mount path.
	paths := make(map[string]string)
	for _, res := range resources {
		if res.Type != "file" {
			continue
		}
		for name := range ids {
			if strings.HasSuffix(res.MountPath, "/workspace/"+name) {
				paths[name] = res.MountPath
			}
		}
	}
	setup, task, finish := paths["setup.sh"], paths["task.md"], paths["finish.sh"]
	for _, mount := range []string{setup, task, finish} {
		if !path.IsAbs(mount) || strings.ContainsAny(mount, " \t\r\n'\x22`$;&|<>()") {
			return "", fmt.Errorf("session response has a missing or invalid mount path %q (%d resources, %d file mounts)",
				mount, len(resources), len(paths))
		}
	}
	if probe && paths[probeScriptName] != path.Join(path.Dir(setup), probeScriptName) {
		return "", errors.New("session response must mount probe.sh next to setup.sh")
	}
	return formatUserMessage(setup, task, finish), nil
}

func formatUserMessage(setup, task, finish string) string {
	return fmt.Sprintf("Set up with: bash %s\nThe task is in: %s\nWhen you are done, run: bash %s\nThen reply DONE.", setup, task, finish)
}
