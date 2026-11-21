package xhttp

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/http"
)

type blockingRoundTripper func(*http.Request) (*http.Response, error)

func (f blockingRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func TestPacketUpWriterCloseReportsFlushTimeout(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	writer := &PacketUpWriter{
		ctx:       ctx,
		cancel:    cancel,
		cfg:       &Config{Host: "example.com", Path: "/xhttp"},
		sessionID: "test-session",
		transport: blockingRoundTripper(func(request *http.Request) (*http.Response, error) {
			<-request.Context().Done()
			return nil, request.Context().Err()
		}),
		buf: []byte("pending payload"),
	}
	writer.writeCond = sync.Cond{L: &writer.writeMu}

	if err := writer.Close(); err == nil {
		t.Fatal("Close() returned nil after cancelling a pending flush")
	}
}

func TestPacketUpWriterCloseBoundsAnInFlightFlush(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan struct{})
	flushDone := make(chan struct{})
	writer := &PacketUpWriter{
		ctx:       ctx,
		cancel:    cancel,
		cfg:       &Config{Host: "example.com", Path: "/xhttp"},
		sessionID: "test-session",
		transport: blockingRoundTripper(func(request *http.Request) (*http.Response, error) {
			close(started)
			<-request.Context().Done()
			return nil, request.Context().Err()
		}),
		buf: []byte("pending payload"),
	}
	writer.writeCond = sync.Cond{L: &writer.writeMu}
	go func() {
		writer.flush()
		close(flushDone)
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("flush did not start")
	}

	begin := time.Now()
	if err := writer.Close(); err == nil {
		t.Fatal("Close() returned nil after timing out an in-flight flush")
	}
	if elapsed := time.Since(begin); elapsed > 2*time.Second {
		t.Fatalf("Close() took %s, want at most 2s", elapsed)
	}
	select {
	case <-flushDone:
	case <-time.After(time.Second):
		t.Fatal("in-flight flush did not stop after Close cancelled its request")
	}
}
