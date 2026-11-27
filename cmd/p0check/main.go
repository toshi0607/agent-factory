package main

import (
	"cmp"
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

func run(args []string, stderr io.Writer, dialOptions ...grpc.DialOption) (result, int) {
	flags := flag.NewFlagSet("p0check", flag.ContinueOnError)
	flags.SetOutput(stderr)
	taskID := flags.String("task", "", "task ID")
	addr := flags.String("addr", "", "emulator host:port")
	timeout := flags.Duration("timeout", 30*time.Second, "connection and check timeout")
	wait := flags.Duration("wait", 0, "separate timeout for retrying the initial connection")
	out := result{Failures: []record.Failure{}}
	parseErr := flags.Parse(args)
	out.Task = *taskID
	if parseErr != nil {
		return out, 2
	}
	host, port, addrErr := net.SplitHostPort(*addr)
	if flags.NArg() != 0 || *taskID == "" || addrErr != nil || host == "" || port == "" || *timeout <= 0 || *wait < 0 {
		fmt.Fprintln(stderr, "usage: p0check -task <id> -addr <host:port> [-timeout 30s] [-wait <duration>]")
		return out, 2
	}
	task, ok := p0.Lookup(*taskID)
	if !ok {
		fmt.Fprintf(stderr, "unknown task %q\n", *taskID)
		return out, 2
	}

	dialOptions = append([]grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithNoProxy(),
	}, dialOptions...)
	conn, err := grpc.NewClient("passthrough:///"+*addr, dialOptions...)
	if err != nil {
		fmt.Fprintf(stderr, "create gRPC client for %s: %v\n", *addr, err)
		return out, 2
	}
	defer func() {
		if err := conn.Close(); err != nil {
			fmt.Fprintf(stderr, "close gRPC connection: %v\n", err)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), cmp.Or(*wait, *timeout))
	defer cancel()
	if err := waitForConnection(ctx, conn); err != nil {
		fmt.Fprintf(stderr, "connect to %s: %v\n", *addr, err)
		return out, 2
	}
	if *wait > 0 {
		cancel()
		checkCtx, cancelCheck := context.WithTimeout(context.Background(), *timeout)
		defer cancelCheck()
		ctx = checkCtx
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

func waitForConnection(ctx context.Context, conn *grpc.ClientConn) error {
	conn.Connect()
	for state := conn.GetState(); state != connectivity.Ready; state = conn.GetState() {
		if !conn.WaitForStateChange(ctx, state) {
			return fmt.Errorf("%w (state %s)", ctx.Err(), state)
		}
	}
	return nil
}
