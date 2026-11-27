package main

import (
	"bytes"
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
)

func TestWaitForLateListener(t *testing.T) {
	listenerCtx, closeListener := context.WithCancel(t.Context())
	defer closeListener()
	listener := pipeListener{listenerCtx, closeListener, make(chan net.Conn)}
	server := grpc.NewServer()
	defer server.Stop()

	firstDial, listening := make(chan struct{}), make(chan struct{})
	markFirstDial := sync.OnceFunc(func() { close(firstDial) })
	serverErrors := make(chan error, 1)
	go func() {
		select {
		case <-firstDial:
		case <-listenerCtx.Done():
			return
		}
		timer := time.NewTimer(300 * time.Millisecond)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-listenerCtx.Done():
			return
		}
		close(listening)
		serverErrors <- server.Serve(listener)
	}()
	dial := func(ctx context.Context, _ string) (net.Conn, error) {
		select {
		case <-listening:
		default:
			markFirstDial()
			return nil, errors.New("listener has not started")
		}
		client, peer := net.Pipe()
		select {
		case listener.connections <- peer:
			return client, nil
		case <-ctx.Done():
		case <-listenerCtx.Done():
		}
		client.Close()
		peer.Close()
		return nil, net.ErrClosed
	}

	var stderr bytes.Buffer
	out, code := run([]string{"-task", "sm-create-get", "-addr", "test:8080", "-timeout", "100ms", "-wait", "5s"}, &stderr,
		grpc.WithContextDialer(dial))
	select {
	case err := <-serverErrors:
		t.Fatalf("late server failed: %v", err)
	default:
	}
	// The late server accepts gRPC connections but implements none of the task's RPCs.
	if code != 1 || len(out.Failures) == 0 {
		t.Fatalf("run = (%d, %+v), stderr = %q; want a completed check that reports missing RPCs", code, out, &stderr)
	}
}

// pipeListener gives gRPC a listener without binding a socket.
type pipeListener struct {
	ctx         context.Context
	cancel      context.CancelFunc
	connections chan net.Conn
}

func (l pipeListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.connections:
		return conn, nil
	case <-l.ctx.Done():
		return nil, net.ErrClosed
	}
}

func (l pipeListener) Close() error {
	l.cancel()
	return nil
}

func (l pipeListener) Addr() net.Addr {
	return &net.TCPAddr{}
}
