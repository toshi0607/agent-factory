package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/toshi0607/agent-factory/judge/google-cloud-emulator/p0"
	"github.com/toshi0607/agent-factory/poc/record"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials/insecure"
)

type result struct {
	Task     string           `json:"task"`
	Passed   bool             `json:"passed"`
	Failures []record.Failure `json:"failures"`
}

func main() {
	out, code := run(os.Args[1:], os.Stderr)
	if err := json.NewEncoder(os.Stdout).Encode(out); err != nil {
		fmt.Fprintln(os.Stderr, err)
		code = 2
	}
	os.Exit(code)
}

func run(args []string, stderr io.Writer) (result, int) {
	flags := flag.NewFlagSet("p0check", flag.ContinueOnError)
	flags.SetOutput(stderr)
	taskID := flags.String("task", "", "task ID")
	addr := flags.String("addr", "", "emulator host:port")
	timeout := flags.Duration("timeout", 30*time.Second, "connection and check timeout")
	out := result{Failures: []record.Failure{}}
	parseErr := flags.Parse(args)
	out.Task = *taskID
	if parseErr != nil {
		return out, 2
	}
	host, port, addrErr := net.SplitHostPort(*addr)
	if flags.NArg() != 0 || *taskID == "" || addrErr != nil || host == "" || port == "" || *timeout <= 0 {
		fmt.Fprintln(stderr, "usage: p0check -task <id> -addr <host:port> [-timeout 30s]")
		return out, 2
	}
	task, ok := p0.Lookup(*taskID)
	if !ok {
		fmt.Fprintf(stderr, "unknown task %q\n", *taskID)
		return out, 2
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	conn, err := grpc.NewClient("passthrough:///"+*addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithNoProxy())
	if err != nil {
		fmt.Fprintf(stderr, "create gRPC client for %s: %v\n", *addr, err)
		return out, 2
	}
	defer func() {
		if err := conn.Close(); err != nil {
			fmt.Fprintf(stderr, "close gRPC connection: %v\n", err)
		}
	}()

	conn.Connect()
	for state := conn.GetState(); state != connectivity.Ready; state = conn.GetState() {
		if !conn.WaitForStateChange(ctx, state) {
			fmt.Fprintf(stderr, "connect to %s: %v (state %s)\n", *addr, ctx.Err(), state)
			return out, 2
		}
	}
	for _, failure := range task.Check(ctx, conn) {
		out.Failures = append(out.Failures, record.Failure{Name: failure.Name, Message: failure.Message})
	}
	out.Passed = len(out.Failures) == 0
	if !out.Passed {
		return out, 1
	}
	return out, 0
}
