//go:build go1.24

package xhttp

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/http"
)

// dialFactory is a maker of one XHTTP client's coalesced h2 transports.
// target and delay decide for every dial by its number (from 1) where it goes
// and how long it waits before TCP: this is how a lost SYN and a block are
// played. tlsDelay, if not nil, is how long the handshake with that number
// (from 1) waits after TCP is up: this is how a slow ClientHello is played.
func dialFactory(t *testing.T, d *dialCounter, target func(n int64) string, delay func(n int64) time.Duration, tlsDelay func(n int64) time.Duration) TransportMaker {
	t.Helper()
	var handshakes atomic.Int64
	mk := CoalesceDials(func() http.RoundTripper {
		return NewTransport(func(ctx context.Context) (net.Conn, error) {
			n := d.dials.Add(1)
			if wait := delay(n); wait > 0 {
				select {
				case <-time.After(wait):
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			}
			c, err := (&net.Dialer{}).DialContext(ctx, "tcp", target(n))
			if err != nil {
				return nil, err
			}
			return d.track(c), nil
		}, func(ctx context.Context, c net.Conn, _ bool) (net.Conn, error) {
			if n := handshakes.Add(1); tlsDelay != nil {
				if wait := tlsDelay(n); wait > 0 {
					select {
					case <-time.After(wait):
					case <-ctx.Done():
						return nil, ctx.Err()
					}
				}
			}
			tc := tls.Client(c, &tls.Config{NextProtos: []string{"h2"}, InsecureSkipVerify: true})
			if err := tc.HandshakeContext(ctx); err != nil {
				return nil, err
			}
			return tc, nil
		}, nil, nil, 0, nil)
	})
	return func() http.RoundTripper {
		rt := mk()
		if _, ok := rt.(*coalescingTransport); !ok {
			t.Fatalf("h2 transport was not wrapped: %T", rt)
		}
		t.Cleanup(func() { rt.(*coalescingTransport).CloseIdleConnections() })
		return rt
	}
}

func okServer(t *testing.T) string {
	return h2TestServer(t, 0, func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })
}

// The client has dialed before; now a cold burst on a fresh transport, and
// the leader's SYN is lost: its dial is stuck before TCP. After
// coalescedBackupAfter a backup starts, like Chrome's backup connect job, and
// the burst goes over it.
func TestCoalesceDialsBackupOnLostSYN(t *testing.T) {
	addr := okServer(t)
	var d dialCounter
	mk := dialFactory(t, &d, func(int64) string { return addr }, func(n int64) time.Duration {
		if n == 2 {
			return 3 * time.Second
		}
		return 0
	}, nil)
	if err := roundTrip(mk(), context.Background()); err != nil {
		t.Fatal(err)
	}
	failed, took := burst(mk(), 30, 5*time.Second)
	if failed != 0 {
		t.Fatalf("%d of 30 requests failed", failed)
	}
	if took >= coalescedBackupAfter+500*time.Millisecond {
		t.Fatalf("burst behind a lost SYN took %v: no backup dial", took)
	}
	if got := d.dials.Load(); got != 3 {
		t.Fatalf("%d dials, want warm-up, the stuck one and one backup", got)
	}
}

// The client's first dial and a single request: the backup waits for neither
// a history nor a second request. Chrome's backup job does not depend on them
// either.
func TestCoalesceDialsBackupForLoneFirstRequest(t *testing.T) {
	addr := okServer(t)
	var d dialCounter
	mk := dialFactory(t, &d, func(int64) string { return addr }, func(n int64) time.Duration {
		if n == 1 {
			return 3 * time.Second
		}
		return 0
	}, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	start := time.Now()
	if err := roundTrip(mk(), ctx); err != nil {
		t.Fatal(err)
	}
	if took := time.Since(start); took > time.Second {
		t.Fatalf("lone request behind a lost SYN took %v", took)
	}
	if got := d.dials.Load(); got != 2 {
		t.Fatalf("%d dials, want the stuck one and one backup", got)
	}
}

// A working path: the dial fits within coalescedBackupAfter, no backups.
func TestCoalesceDialsBackupQuietOnHealthyPath(t *testing.T) {
	addr := okServer(t)
	var d dialCounter
	mk := dialFactory(t, &d, func(int64) string { return addr }, func(n int64) time.Duration {
		if n == 1 {
			return 0
		}
		return 100 * time.Millisecond
	}, nil)
	if err := roundTrip(mk(), context.Background()); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if failed, _ := burst(mk(), 30, 5*time.Second); failed != 0 {
			t.Fatalf("burst %d: %d of 30 requests failed", i, failed)
		}
	}
	if got := d.dials.Load(); got != 4 {
		t.Fatalf("%d dials for warm-up and three cold bursts, want 4", got)
	}
}

// The leader's TCP is up at once, and the handshake takes 600 ms. A browser
// sends no second ClientHello for a slow handshake, and neither do we: no
// backup and no dials of the followers' own; the burst waits for the leader
// and goes over one connection.
func TestCoalesceDialsOneConnOnSlowHandshake(t *testing.T) {
	addr := okServer(t)
	var d dialCounter
	mk := dialFactory(t, &d, func(int64) string { return addr }, func(int64) time.Duration { return 0 }, func(n int64) time.Duration {
		if n == 2 {
			return 600 * time.Millisecond
		}
		return 0
	})
	if err := roundTrip(mk(), context.Background()); err != nil {
		t.Fatal(err)
	}
	failed, took := burst(mk(), 30, 5*time.Second)
	if failed != 0 {
		t.Fatalf("%d of 30 requests failed", failed)
	}
	if got := d.dials.Load(); got != 2 {
		t.Fatalf("%d dials, want warm-up and the slow one: no second ClientHello while a handshake runs", got)
	}
	if took < 600*time.Millisecond {
		t.Fatalf("burst took %v, faster than its only handshake", took)
	}
}

// The backup dial is refused at once (a reset, a closed port), and the stuck
// leader connects after 600 ms. The backup's refusal does not fail the burst:
// the leader connects, and everyone goes over it.
func TestCoalesceDialsFailedBackupKeepsLeader(t *testing.T) {
	addr := okServer(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	refused := ln.Addr().String()
	ln.Close()
	var d dialCounter
	mk := dialFactory(t, &d, func(n int64) string {
		if n <= 2 {
			return addr
		}
		return refused
	}, func(n int64) time.Duration {
		if n == 2 {
			return 600 * time.Millisecond
		}
		return 0
	}, nil)
	if err := roundTrip(mk(), context.Background()); err != nil {
		t.Fatal(err)
	}
	failed, took := burst(mk(), 30, 5*time.Second)
	if failed != 0 {
		t.Fatalf("%d of 30 requests failed with the backup's error", failed)
	}
	if took >= time.Second {
		t.Fatalf("burst took %v: waited past the leader's dial", took)
	}
	if got := d.dials.Load(); got != 3 {
		t.Fatalf("%d dials, want warm-up, the slow leader and the refused backup", got)
	}
}

// A block after the ClientHello: TCP comes up, there is no backup, and while
// an attempt hangs no second one starts: attempts replace each other by
// coalescedAttemptTimeout, and one socket is in flight.
func TestCoalesceDialsOneAttemptOnBlackhole(t *testing.T) {
	addr := okServer(t)
	hole := blackholeServer(t)
	var d dialCounter
	mk := dialFactory(t, &d, func(n int64) string {
		if n == 1 {
			return addr
		}
		return hole
	}, func(int64) time.Duration { return 0 }, nil)
	warm := mk()
	if err := roundTrip(warm, context.Background()); err != nil {
		t.Fatal(err)
	}
	warm.(*coalescingTransport).CloseIdleConnections()
	waitFor(t, "the warm-up connection to close", time.Second, func() bool { return d.open.Load() == 0 })
	failed, _ := burst(mk(), 50, 2500*time.Millisecond)
	if failed != 50 {
		t.Fatalf("%d of 50 requests failed, want all", failed)
	}
	want := int64(2500*time.Millisecond/coalescedAttemptTimeout) + 1
	if got := d.dials.Load() - 1; got != want {
		t.Fatalf("%d dials into the blackhole in 2.5s, want %d: one per attempt bound", got, want)
	}
	if got := d.maxOpen.Load(); got > 1 {
		t.Fatalf("%d sockets open at once, want 1", got)
	}
	waitFor(t, "abandoned dials to close", 2*time.Second, func() bool { return d.open.Load() == 0 })
}

// lagConn is a connection over a link with a delay of rtt: everything the
// server sends arrives rtt after it was sent. Writes go out at once, so a
// request-response round costs one rtt, as on a real link.
type lagConn struct {
	net.Conn
	rtt    time.Duration
	chunks chan lagChunk
	buf    []byte
	err    error
}

type lagChunk struct {
	data []byte
	at   time.Time
	err  error
}

func newLagConn(c net.Conn, rtt time.Duration) *lagConn {
	l := &lagConn{Conn: c, rtt: rtt, chunks: make(chan lagChunk, 64)}
	go func() {
		for {
			b := make([]byte, 32<<10)
			n, err := c.Read(b)
			l.chunks <- lagChunk{b[:n], time.Now().Add(rtt), err}
			if err != nil {
				return
			}
		}
	}()
	return l
}

func (l *lagConn) Read(b []byte) (int, error) {
	for len(l.buf) == 0 {
		if l.err != nil {
			return 0, l.err
		}
		ch := <-l.chunks
		time.Sleep(time.Until(ch.at))
		l.buf, l.err = ch.data, ch.err
	}
	n := copy(b, l.buf)
	l.buf = l.buf[n:]
	return n, nil
}

// A slow but live link: TCP comes up in rtt, the handshake takes another rtt,
// 2.5 and 4 s in all, longer than coalescedAttemptTimeout. An attempt is
// replaced rather than joined by a parallel one, but such an attempt is not
// cut: the bound grows with the time TCP took and is extended while the
// server keeps sending bytes.
func TestCoalesceDialsSlowAliveHandshake(t *testing.T) {
	addr := okServer(t)
	for _, rtt := range []time.Duration{1250 * time.Millisecond, 2 * time.Second} {
		var d dialCounter
		mk := CoalesceDials(func() http.RoundTripper {
			return NewTransport(func(ctx context.Context) (net.Conn, error) {
				d.dials.Add(1)
				select {
				case <-time.After(rtt):
				case <-ctx.Done():
					return nil, ctx.Err()
				}
				c, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
				if err != nil {
					return nil, err
				}
				return newLagConn(d.track(c), rtt), nil
			}, func(ctx context.Context, c net.Conn, _ bool) (net.Conn, error) {
				tc := tls.Client(c, &tls.Config{NextProtos: []string{"h2"}, InsecureSkipVerify: true})
				if err := tc.HandshakeContext(ctx); err != nil {
					return nil, err
				}
				return tc, nil
			}, nil, nil, 0, nil)
		})
		rt := mk()
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		start := time.Now()
		err := roundTrip(rt, ctx)
		cancel()
		rt.(*coalescingTransport).CloseIdleConnections()
		if err != nil {
			t.Fatalf("rtt %v: request over a slow live path failed after %v: %v", rtt, time.Since(start), err)
		}
		// The leader and maybe a backup: TCP takes longer than
		// coalescedBackupAfter.
		if got := d.dials.Load(); got > 2 {
			t.Fatalf("rtt %v: %d dials, want no attempt cut on a live path", rtt, got)
		}
	}
}

// helloCounter is a proxy in front of addr that counts the connections that
// have sent at least one byte, that is, started a handshake, and lets them
// through to the server after delay: the handshake is not instant.
func helloCounter(t *testing.T, addr string, delay time.Duration, hellos *atomic.Int64) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				first := make([]byte, 1)
				if _, err := io.ReadFull(c, first); err != nil {
					return
				}
				hellos.Add(1)
				time.Sleep(delay)
				u, err := net.Dial("tcp", addr)
				if err != nil {
					return
				}
				defer u.Close()
				u.Write(first)
				go func() { io.Copy(u, c); u.Close() }()
				io.Copy(c, u)
			}()
		}
	}()
	return ln.Addr().String()
}

// TCP takes longer than coalescedBackupAfter (DNS on the first dial, a
// dialer-proxy, a long RTT), and the backup dial reaches it too. Only the one
// that got there first goes on: one handshake goes to the server.
func TestCoalesceDialsOneHandshakeAfterSlowTCP(t *testing.T) {
	var hellos atomic.Int64
	addr := helloCounter(t, okServer(t), 300*time.Millisecond, &hellos)
	var d dialCounter
	mk := dialFactory(t, &d, func(int64) string { return addr }, func(int64) time.Duration { return 300 * time.Millisecond }, nil)
	failed, _ := burst(mk(), 30, 5*time.Second)
	if failed != 0 {
		t.Fatalf("%d of 30 requests failed", failed)
	}
	if got := d.dials.Load(); got != 2 {
		t.Fatalf("%d dials, want the leader and its backup", got)
	}
	if got := hellos.Load(); got != 1 {
		t.Fatalf("%d handshakes reached the server, want 1", got)
	}
}

// XHTTP without TLS: wrapTLS returns the connection as it is, having written
// nothing, and the dial that gave TCP way to the other returns with no error.
// It comes first (the leader has not returned yet), but the attempt hands out
// the leader's connection, not the closed one of the dial that gave way.
func TestCoalesceDialsBackupLostTCPWithoutTLS(t *testing.T) {
	var n atomic.Int64
	var leaderConn net.Conn
	dial := func(ctx context.Context, _, _ string) (net.Conn, error) {
		c, peer := net.Pipe()
		t.Cleanup(func() { c.Close(); peer.Close() })
		switch n.Add(1) {
		case 1:
			// The leader: TCP in 300 ms, before the backup, and it returns
			// 100 ms after that.
			time.Sleep(300 * time.Millisecond)
			w := DialTCPUp(ctx, c)
			leaderConn = w
			time.Sleep(100 * time.Millisecond)
			return w, nil
		default:
			// The backup: started after coalescedBackupAfter, reaches TCP
			// second and returns at once, as without TLS.
			time.Sleep(100 * time.Millisecond)
			return DialTCPUp(ctx, c), nil
		}
	}
	a := &dialAttempt{start: time.Now(), tcpUp: make(chan struct{})}
	conn, err := dialWithBackup(context.Background(), a, dial, "tcp", "x")
	if err != nil {
		t.Fatal(err)
	}
	if _, lost := conn.(secondConn); lost {
		t.Fatal("the attempt returned the closed conn of the dial that lost TCP")
	}
	if conn != leaderConn {
		t.Fatalf("the attempt returned %T, want the leader's conn", conn)
	}
	if got := n.Load(); got != 2 {
		t.Fatalf("%d dials, want the leader and its backup", got)
	}
}

// The leader's connection is busy with the leader's own long request (a limit
// of one stream), and the leader's RoundTrip will not return before the
// session ends. A request that comes while the successful leader holds its
// place gets the busy connection from net/http, searches again and dials by
// itself at once rather than waiting for the leader until its session ends.
func TestCoalesceDialsFollowerOfLongLeader(t *testing.T) {
	release := make(chan struct{})
	addr := h2TestServer(t, 1, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/long" {
			w.WriteHeader(http.StatusOK)
			w.(http.Flusher).Flush()
			select {
			case <-release:
			case <-r.Context().Done():
			}
			return
		}
		w.Write([]byte("ok"))
	})
	var d dialCounter
	rt := coalescedTestTransport(t, addr, &d, 0)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", "https://example.com/long", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		close(release)
		resp.Body.Close()
	}()

	start := time.Now()
	ctx2, cancel2 := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel2()
	if err := roundTrip(rt, ctx2); err != nil {
		t.Fatalf("request behind a busy leader connection failed after %v: %v", time.Since(start), err)
	}
	if took := time.Since(start); took > time.Second {
		t.Fatalf("request behind a busy leader connection took %v", took)
	}
	if got := d.dials.Load(); got != 2 {
		t.Fatalf("%d dials, want the leader and one for the second request", got)
	}
}
