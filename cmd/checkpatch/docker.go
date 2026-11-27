package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/toshi0607/agent-factory/poc/record"
)

const (
	productPort          = "8080"
	productAlias         = "product"
	dockerBuildTimeout   = 10 * time.Minute
	dockerJudgeTimeout   = 5 * time.Minute
	dockerControlTimeout = 10 * time.Second
	maxProductLogSize    = 1 << 20
)

func runDockerCheck(ctx context.Context, opt options, tree string, out *record.CheckResult, stderr io.Writer) (int, error) {
	buildOut := filepath.Join(opt.work, "build-out")
	productOut := filepath.Join(opt.work, "product-out")
	judgeOut := filepath.Join(opt.work, "judge-out")
	for _, dir := range []string{buildOut, productOut, judgeOut, filepath.Join(opt.work, "gocache")} {
		if err := os.Mkdir(dir, 0o755); err != nil {
			return 2, fmt.Errorf("create %s: %w", dir, err)
		}
	}

	name := "p0-check-" + strings.ToLower(rand.Text())
	buildName, network := name+"-build", name+"-net"
	productName, judgeName := name+"-product", name+"-judge"
	uid, gid := os.Getuid(), os.Getgid()

	buildLog := filepath.Join(opt.work, "build-script.log")
	buildCtx, cancelBuild := context.WithTimeout(ctx, dockerBuildTimeout)
	code, err := runToLogs(buildCtx, buildLog, buildLog, 0, "docker", buildDockerArgs(opt, tree, buildOut, buildName, uid, gid)...)
	interrupted := buildCtx.Err() != nil
	cancelBuild()
	switch {
	case err != nil:
		if interrupted {
			cleanupDocker(stderr, "rm", "-f", buildName)
		}
		return 2, fmt.Errorf("run build container: %w", err)
	case code == 11:
		return 1, fmt.Errorf("build failed; see %s", filepath.Join(buildOut, "build.log"))
	case code != 0:
		return 2, fmt.Errorf("build container exited %d; see %s", code, buildLog)
	}
	out.BuildOK = true
	if err := ctx.Err(); err != nil {
		return 2, err
	}

	// Arm cleanup before creation in case the client is interrupted after Docker creates the resource.
	defer cleanupDocker(stderr, "network", "rm", network)
	networkCtx, cancelNetwork := context.WithTimeout(ctx, dockerControlTimeout)
	var networkLog bytes.Buffer
	// An isolated bridge has no host-side address for the product to reach.
	code, err = runCommand(networkCtx, io.Discard, &networkLog, "docker", "network", "create",
		"--internal", "--opt", "com.docker.network.bridge.gateway_mode_ipv4=isolated", network)
	cancelNetwork()
	if err != nil {
		return 2, fmt.Errorf("create check network: %w", err)
	}
	if code != 0 {
		return 2, fmt.Errorf("create check network: docker exited %d: %s", code, strings.TrimSpace(networkLog.String()))
	}

	judgeInterrupted := false
	defer func() {
		cleanupProduct(stderr, productName, productOut)
		if judgeInterrupted {
			cleanupDocker(stderr, "rm", "-f", judgeName)
		}
	}()
	startLog := filepath.Join(productOut, "start.log")
	startCtx, cancelStart := context.WithTimeout(ctx, dockerControlTimeout)
	code, err = runToLogs(startCtx, startLog, startLog, 0, "docker", productDockerArgs(opt, buildOut, network, productName, uid, gid)...)
	cancelStart()
	if err != nil {
		return 2, fmt.Errorf("start product container: %w", err)
	}
	if code != 0 {
		if code == 126 || code == 127 {
			return 1, fmt.Errorf("product container could not run the emulator (exit %d); see %s", code, startLog)
		}
		return 2, fmt.Errorf("start product container: docker exited %d; see %s", code, startLog)
	}

	judgeLog := filepath.Join(judgeOut, "p0check.log")
	judgeCtx, cancelJudge := context.WithTimeout(ctx, dockerJudgeTimeout)
	code, err = runToLogs(judgeCtx, filepath.Join(judgeOut, "p0check.json"), judgeLog, 0, "docker",
		judgeDockerArgs(opt, judgeOut, network, judgeName, uid, gid)...)
	judgeInterrupted = judgeCtx.Err() != nil
	cancelJudge()
	switch {
	case err != nil:
		return 2, fmt.Errorf("run judge container: %w", err)
	case code == 2:
		return 1, fmt.Errorf("p0check could not run; see %s", judgeLog)
	case code != 0 && code != 1:
		return 2, fmt.Errorf("judge container exited %d; see %s", code, judgeLog)
	}
	return code, nil
}

func cleanupProduct(stderr io.Writer, name, output string) {
	defer cleanupDocker(stderr, "rm", "-f", name)
	cleanupDocker(stderr, "kill", name)
	ctx, cancel := context.WithTimeout(context.Background(), dockerControlTimeout)
	defer cancel()
	logPath := filepath.Join(output, "emulator.log")
	if code, err := runToLogs(ctx, logPath, logPath, maxProductLogSize, "docker", "logs", name); err != nil || code != 0 {
		fmt.Fprintf(stderr, "docker logs %s: exit %d (%v); see %s\n", name, code, err, logPath)
	}
}

func cleanupDocker(stderr io.Writer, args ...string) {
	ctx, cancel := context.WithTimeout(context.Background(), dockerControlTimeout)
	defer cancel()
	var log bytes.Buffer
	code, err := runCommand(ctx, io.Discard, &log, "docker", args...)
	if err != nil {
		fmt.Fprintf(stderr, "docker %s: %v\n", strings.Join(args, " "), err)
	} else if code != 0 {
		detail := strings.TrimSpace(log.String())
		if args[0] == "kill" && strings.HasSuffix(detail, "is not running") {
			return
		}
		fmt.Fprintf(stderr, "docker %s: exit %d: %s\n", strings.Join(args, " "), code, detail)
	}
}

func dockerArgs(uid, gid int, options ...string) []string {
	return append(append([]string{"run"}, options...),
		"--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--pids-limit", "1024", "--memory", "4g",
		"--user", strconv.Itoa(uid)+":"+strconv.Itoa(gid))
}

func dockerGoArgs(opt options, output, cache string, uid, gid int, options ...string) []string {
	return append(dockerArgs(uid, gid, options...),
		"--tmpfs", "/tmp:rw,exec,size=512m",
		"-e", "HOME=/tmp", "-e", "GOCACHE=/gocache", "-e", "GOMODCACHE=/modcache",
		"-e", "GOFLAGS=-mod=readonly", "-e", "GOPROXY=off", "-e", "GOTOOLCHAIN=local",
		"-v", output+":/out", "-v", filepath.Join(opt.work, cache)+":/gocache", "-w", "/tree")
}

func generationDockerArgs(opt options, tree, output string, uid, gid int) []string {
	return append(dockerGoArgs(opt, output, "gen-gocache", uid, gid, "--rm", "--network", "none"),
		"-v", tree+":/tree", "-v", opt.modcache+":/modcache:ro", "-v", opt.genScript+":/p0-gen-tree.sh:ro",
		opt.image, "bash", "/p0-gen-tree.sh", "/tree", "/out")
}

func buildDockerArgs(opt options, tree, output, name string, uid, gid int) []string {
	return append(dockerGoArgs(opt, output, "gocache", uid, gid, "--rm", "--network", "none", "--name", name),
		"-v", tree+":/tree:ro", "-v", opt.modcache+":/modcache:ro", "-v", opt.buildScript+":/p0-build-tree.sh:ro",
		opt.image, "bash", "/p0-build-tree.sh", "/tree", "/out")
}

func productDockerArgs(opt options, buildOut, network, name string, uid, gid int) []string {
	if uid == 0 {
		uid = 65534
	}
	if gid == 0 {
		gid = 65534
	}
	return append(dockerArgs(uid, gid, "--detach", "--name", name, "--network", network, "--network-alias", productAlias),
		"--read-only", "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=16m",
		"--log-driver", "local", "--log-opt", "max-size=1m", "--log-opt", "max-file=1", "--log-opt", "compress=false",
		"-v", buildOut+":/product:ro", "--entrypoint", "/product/emulator",
		opt.image, "-addr", "0.0.0.0:"+productPort)
}

func judgeDockerArgs(opt options, output, network, name string, uid, gid int) []string {
	return append(dockerArgs(uid, gid, "--rm", "--name", name, "--network", network),
		"-v", opt.p0check+":/p0check:ro", "-v", output+":/out", "--entrypoint", "/p0check",
		opt.image, "-task", opt.taskID, "-addr", productAlias+":"+productPort, "-wait", "30s")
}
