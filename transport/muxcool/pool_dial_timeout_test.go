package muxcool

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

// With CarrierDialTimeout the calls that wait for a carrier being dialed do
// not fail at their own deadline: an xdrive session takes some seconds to
// start, longer than the tunnel's dial timeout.
func TestPoolWaitersOutliveTheirDeadlineForASlowCarrier(t *testing.T) {
	dialer := newBlockingCarrierDialer()
	options := testPoolOptions()
	options.CarrierDialTimeout = 10 * time.Second
	pool := NewPool(dialer.dial, options)
	t.Cleanup(func() { _ = pool.Close() })

	const callers = 4
	type result struct {
		conn net.Conn
		err  error
	}
	results := make(chan result, callers)
	for i := 0; i < callers; i++ {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
			defer cancel()
			conn, err := pool.DialContext(ctx, "slow.example", 443)
			results <- result{conn, err}
		}()
	}
	select {
	case <-dialer.started:
	case <-time.After(time.Second):
		t.Fatal("carrier dial did not start")
	}
	time.Sleep(200 * time.Millisecond)
	close(dialer.release)

	for i := 0; i < callers; i++ {
		select {
		case r := <-results:
			if r.err != nil {
				t.Fatalf("a call failed while the carrier was being dialed: %v", r.err)
			}
			_ = r.conn.Close()
		case <-time.After(2 * time.Second):
			t.Fatal("a call did not complete")
		}
	}
	if got := dialer.callCount(); got != 1 {
		t.Fatalf("carrier dials = %d, want 1", got)
	}
}

// A call canceled for a reason other than its deadline stops waiting.
func TestPoolSlowCarrierWaitHonorsCancel(t *testing.T) {
	dialer := newBlockingCarrierDialer()
	options := testPoolOptions()
	options.CarrierDialTimeout = 10 * time.Second
	pool := NewPool(dialer.dial, options)
	t.Cleanup(func() {
		close(dialer.release)
		_ = pool.Close()
	})

	go func() { _, _ = pool.DialContext(context.Background(), "first.example", 443) }()
	select {
	case <-dialer.started:
	case <-time.After(time.Second):
		t.Fatal("carrier dial did not start")
	}

	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, err := pool.DialContext(ctx, "second.example", 443)
		result <- err
	}()
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("error = %v, want %v", err, context.Canceled)
		}
	case <-time.After(time.Second):
		t.Fatal("a canceled call kept waiting for the carrier")
	}
}

// Pool.Close ends a carrier dial in flight, though the dial does not end at
// the deadline of the call that started it.
func TestPoolCloseCancelsSlowCarrierDial(t *testing.T) {
	dialEnded := make(chan error, 1)
	started := make(chan struct{})
	dial := func(ctx context.Context) (net.Conn, error) {
		close(started)
		<-ctx.Done()
		dialEnded <- ctx.Err()
		return nil, ctx.Err()
	}
	options := testPoolOptions()
	options.CarrierDialTimeout = time.Minute
	pool := NewPool(dial, options)

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		defer cancel()
		_, _ = pool.DialContext(ctx, "slow.example", 443)
	}()
	<-started
	time.Sleep(100 * time.Millisecond)
	select {
	case err := <-dialEnded:
		t.Fatalf("the carrier dial ended at the caller's deadline: %v", err)
	default:
	}
	_ = pool.Close()
	select {
	case err := <-dialEnded:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("dial ended with %v, want %v", err, context.Canceled)
		}
	case <-time.After(time.Second):
		t.Fatal("Pool.Close did not cancel the carrier dial")
	}
}

func TestWithoutDeadline(t *testing.T) {
	type key struct{}
	parent, cancelParent := context.WithTimeout(context.WithValue(context.Background(), key{}, "v"), 10*time.Millisecond)
	defer cancelParent()
	ctx, cancel := WithoutDeadline(parent, time.Minute)
	defer cancel()
	if ctx.Value(key{}) != "v" {
		t.Fatal("the values of the parent are lost")
	}
	<-parent.Done()
	select {
	case <-ctx.Done():
		t.Fatal("the context ended at the parent's deadline")
	case <-time.After(50 * time.Millisecond):
	}

	parent, cancelParent = context.WithCancel(context.Background())
	ctx, cancel = WithoutDeadline(parent, time.Minute)
	defer cancel()
	cancelParent()
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("the context did not end with the parent's cancel")
	}

	ctx, cancel = WithoutDeadline(context.Background(), 10*time.Millisecond)
	defer cancel()
	select {
	case <-ctx.Done():
		if !errors.Is(ctx.Err(), context.DeadlineExceeded) {
			t.Fatalf("err = %v", ctx.Err())
		}
	case <-time.After(time.Second):
		t.Fatal("the context did not end at its own timeout")
	}
}
