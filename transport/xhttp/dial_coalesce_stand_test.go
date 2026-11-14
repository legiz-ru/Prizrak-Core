//go:build go1.24

package xhttp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/http"
	"github.com/metacubex/http/httptest"
)

// The scenarios of the manual stand (mihomo -> relay -> Xray) on the full path
// of the XHTTP client: NewClient and the XHTTP server over TLS h2 with a relay
// between them that counts connections and can act as a block after the ClientHello.

// standRelay is a TCP relay in front of the server. In block mode new connections
// are accepted and read, but nothing goes upstream and nothing comes back. freeze
// is how many of the next connections to freeze the same way while the path
// works. delay (ns) is a pause before a connection goes upstream: TCP with the
// client is up already, and the handshake is not instant, as on a link with an
// RTT.
type standRelay struct {
	ln       net.Listener
	upstream string
	blocked  atomic.Bool
	freeze   atomic.Int64
	delay    atomic.Int64
	accepted atomic.Int64
	open     atomic.Int64
	peak     atomic.Int64
	mu       sync.Mutex
	conns    map[net.Conn]struct{}
}

func newStandRelay(t *testing.T, upstream string) *standRelay {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	r := &standRelay{ln: ln, upstream: upstream, conns: map[net.Conn]struct{}{}}
	t.Cleanup(func() {
		ln.Close()
		r.kill()
	})
	go r.serve()
	return r
}

func (r *standRelay) addr() string { return r.ln.Addr().String() }

func (r *standRelay) takeFreeze() bool {
	for n := r.freeze.Load(); n > 0; n = r.freeze.Load() {
		if r.freeze.CompareAndSwap(n, n-1) {
			return true
		}
	}
	return false
}

func (r *standRelay) track(c net.Conn) {
	r.mu.Lock()
	r.conns[c] = struct{}{}
	r.mu.Unlock()
}

func (r *standRelay) untrack(c net.Conn) {
	r.mu.Lock()
	delete(r.conns, c)
	r.mu.Unlock()
}

// kill drops every connection through the relay, like a broken path.
func (r *standRelay) kill() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for c := range r.conns {
		c.Close()
	}
}

func (r *standRelay) reset() { r.accepted.Store(0); r.peak.Store(r.open.Load()) }

func (r *standRelay) serve() {
	for {
		c, err := r.ln.Accept()
		if err != nil {
			return
		}
		r.accepted.Add(1)
		n := r.open.Add(1)
		for m := r.peak.Load(); n > m && !r.peak.CompareAndSwap(m, n); m = r.peak.Load() {
		}
		// Register before the goroutine starts: kill must not miss a
		// connection just accepted.
		r.track(c)
		go func() {
			defer r.open.Add(-1)
			defer r.untrack(c)
			defer c.Close()
			if r.blocked.Load() || r.takeFreeze() {
				io.Copy(io.Discard, c)
				return
			}
			if d := r.delay.Load(); d > 0 {
				time.Sleep(time.Duration(d))
			}
			up, err := net.Dial("tcp", r.upstream)
			if err != nil {
				return
			}
			r.track(up)
			defer r.untrack(up)
			defer up.Close()
			done := make(chan struct{}, 2)
			go func() { io.Copy(up, c); up.Close(); done <- struct{}{} }()
			go func() { io.Copy(c, up); c.Close(); done <- struct{}{} }()
			<-done
			<-done
		}()
	}
}

// standServer is the XHTTP server over TLS h2 with an echo.
func standServer(t *testing.T, mode string) string {
	t.Helper()
	handler, err := NewServerHandler(ServerOption{
		Config: Config{Path: "/xhttp", Mode: mode, ScStreamUpServerSecs: "0"},
		ConnHandler: func(conn net.Conn) {
			defer conn.Close()
			io.Copy(conn, conn)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(handler)
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv.Listener.Addr().String()
}

// standClient builds the XHTTP client the way vless.go does. wrap, when set,
// wraps the transport maker from outside, as the flow governor does upstream.
func standClient(t *testing.T, addr, mode string, reuse *ReuseConfig, wrap func(TransportMaker) TransportMaker) *Client {
	t.Helper()
	var mk TransportMaker = func() http.RoundTripper {
		return NewTransport(func(ctx context.Context) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", addr)
		}, func(ctx context.Context, c net.Conn, _ bool) (net.Conn, error) {
			tc := tls.Client(c, &tls.Config{NextProtos: []string{"h2"}, InsecureSkipVerify: true})
			if err := tc.HandshakeContext(ctx); err != nil {
				return nil, err
			}
			return tc, nil
		}, nil, nil, 0, nil)
	}
	if wrap != nil {
		mk = wrap(mk)
	}
	client, err := NewClient(&Config{Host: "example.com", Path: "/xhttp", Mode: mode, ReuseConfig: reuse}, mk, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	return client
}

// echoSession sends size bytes through a session and checks the SHA-256.
func echoSession(client *Client, timeout time.Duration, size int, seed int) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	conn, err := client.Dial(ctx)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))
	msg := make([]byte, size)
	for i := range msg {
		msg[i] = byte((i*7 + seed) % 251)
	}
	errc := make(chan error, 1)
	go func() {
		_, err := conn.Write(msg)
		errc <- err
	}()
	h := sha256.New()
	if _, err := io.CopyN(h, conn, int64(size)); err != nil {
		return fmt.Errorf("read: %w", err)
	}
	if err := <-errc; err != nil {
		return fmt.Errorf("write: %w", err)
	}
	if want := sha256.Sum256(msg); !bytes.Equal(h.Sum(nil), want[:]) {
		return fmt.Errorf("echo mismatch")
	}
	return nil
}

func sessions(client *Client, n int, timeout time.Duration, size int) (failed int64, firstErr error) {
	var wg sync.WaitGroup
	var fails atomic.Int64
	var once sync.Once
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if err := echoSession(client, timeout, size, i); err != nil {
				fails.Add(1)
				once.Do(func() { firstErr = err })
			}
		}(i)
	}
	wg.Wait()
	return fails.Load(), firstErr
}

// A working server, every mode: a cold burst of 50 sessions opens exactly
// max-connections connections, a warm one none, and the data arrives intact.
// Without reuse-settings a connection per session is intended and stays.
func TestCoalesceDialsStandModes(t *testing.T) {
	for _, mode := range []string{"stream-one", "stream-up", "packet-up"} {
		for _, reuse := range []bool{true, false} {
			name := mode + "/reuse"
			if !reuse {
				name = mode + "/noreuse"
			}
			t.Run(name, func(t *testing.T) {
				leakCheck(t)
				relay := newStandRelay(t, standServer(t, mode))
				var rc *ReuseConfig
				if reuse {
					rc = &ReuseConfig{MaxConnections: "2"}
				}
				client := standClient(t, relay.addr(), mode, rc, nil)

				if failed, err := sessions(client, 50, 10*time.Second, 32<<10); failed != 0 {
					t.Fatalf("cold: %d of 50 sessions failed: %v", failed, err)
				}
				cold := relay.accepted.Load()
				relay.reset()
				if failed, err := sessions(client, 50, 10*time.Second, 32<<10); failed != 0 {
					t.Fatalf("warm: %d of 50 sessions failed: %v", failed, err)
				}
				warm := relay.accepted.Load()
				if failed, err := sessions(client, 3, 30*time.Second, 4<<20); failed != 0 {
					t.Fatalf("4 MiB: %d of 3 sessions failed: %v", failed, err)
				}
				if reuse {
					if cold != 2 || warm != 0 {
						t.Fatalf("max-connections=2: cold burst opened %d connections, warm %d; want 2 and 0", cold, warm)
					}
				} else if cold != 50 {
					t.Fatalf("without reuse-settings: cold burst opened %d connections, want one per session (50)", cold)
				}
			})
		}
	}
}

// An outer wrapper replaces DialTLSContext before the coalescing, as the flow
// governor does upstream: coalescing works on top of it, and every connection goes through the wrapper.
func TestCoalesceDialsStandWrappedDial(t *testing.T) {
	leakCheck(t)
	relay := newStandRelay(t, standServer(t, "stream-up"))
	var wrapped atomic.Int64
	wrap := func(mk TransportMaker) TransportMaker {
		return func() http.RoundTripper {
			rt := mk()
			tr := rt.(*http.Transport)
			dial := tr.DialTLSContext
			tr.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
				c, err := dial(ctx, network, addr)
				if err == nil {
					wrapped.Add(1)
				}
				return c, err
			}
			return rt
		}
	}
	client := standClient(t, relay.addr(), "stream-up", &ReuseConfig{MaxConnections: "2"}, wrap)

	if failed, err := sessions(client, 50, 10*time.Second, 32<<10); failed != 0 {
		t.Fatalf("%d of 50 sessions failed: %v", failed, err)
	}
	if got := relay.accepted.Load(); got != 2 {
		t.Fatalf("%d connections with an outer dial wrapper, want 2", got)
	}
	if got := wrapped.Load(); got != 2 {
		t.Fatalf("outer wrapper saw %d connections, want 2", got)
	}
}

// A block after the ClientHello on a cold pool: live connections are dropped,
// new ones hang. Two waves of sessions open no more than two sockets per
// transport (the leader and a backup: after the warm-up the client has a
// history) and leave none hanging; once the block is lifted, sessions go at
// once.
func TestCoalesceDialsStandBlackhole(t *testing.T) {
	leakCheck(t)
	setDialTimeout(t, 2*time.Second)
	relay := newStandRelay(t, standServer(t, "stream-one"))
	client := standClient(t, relay.addr(), "stream-one", &ReuseConfig{MaxConnections: "2"}, nil)

	if failed, err := sessions(client, 20, 10*time.Second, 1<<10); failed != 0 {
		t.Fatalf("warm-up: %d of 20 sessions failed: %v", failed, err)
	}
	relay.blocked.Store(true)
	relay.kill()
	waitFor(t, "relayed connections to drop", 2*time.Second, func() bool { return relay.open.Load() == 0 })

	for wave := 1; wave <= 2; wave++ {
		relay.reset()
		if failed, _ := sessions(client, 50, 700*time.Millisecond, 1<<10); failed != 50 {
			t.Fatalf("wave %d: %d of 50 sessions failed, want all", wave, failed)
		}
		if got := relay.peak.Load(); got > 4 {
			t.Fatalf("wave %d: %d sockets open at once, want at most 4", wave, got)
		}
		waitFor(t, "abandoned dials to end", time.Second, func() bool { return relay.open.Load() == 0 })
	}

	relay.blocked.Store(false)
	relay.reset()
	start := time.Now()
	if failed, err := sessions(client, 30, 5*time.Second, 1<<10); failed != 0 {
		t.Fatalf("after unblock: %d of 30 sessions failed: %v", failed, err)
	}
	if took := time.Since(start); took > time.Second {
		t.Fatalf("recovery after unblock took %v", took)
	}
	if got := relay.accepted.Load(); got > 2 {
		t.Fatalf("recovery opened %d connections, want at most 2", got)
	}
}

// Downloads cut off mid-transfer do not break the pool: new sessions go over
// the same connections, and no goroutines are left.
func TestCoalesceDialsStandAborts(t *testing.T) {
	leakCheck(t)
	relay := newStandRelay(t, standServer(t, "stream-up"))
	client := standClient(t, relay.addr(), "stream-up", &ReuseConfig{MaxConnections: "2"}, nil)

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			conn, err := client.Dial(ctx)
			if err != nil {
				return
			}
			conn.SetDeadline(time.Now().Add(5 * time.Second))
			go conn.Write(make([]byte, 8<<20))
			io.CopyN(io.Discard, conn, 256<<10)
			conn.Close()
		}()
	}
	wg.Wait()
	if failed, err := sessions(client, 20, 10*time.Second, 256<<10); failed != 0 {
		t.Fatalf("after aborts: %d of 20 sessions failed: %v", failed, err)
	}
	if got := relay.accepted.Load(); got != 2 {
		t.Fatalf("%d connections, want 2", got)
	}
}

// A page starts loading during a block, its sessions come one after another,
// and the block is lifted in the middle of the burst. The hung leader does not
// hold the burst: every session that came after the block was lifted gets
// through, and some of those started during the block get the new connection
// too. Only a few sockets are used.
func TestCoalesceDialsStandBlockDuringPage(t *testing.T) {
	leakCheck(t)
	setDialTimeout(t, 3*time.Second)
	relay := newStandRelay(t, standServer(t, "stream-one"))
	client := standClient(t, relay.addr(), "stream-one", &ReuseConfig{MaxConnections: "2"}, nil)
	relay.blocked.Store(true)

	const n = 48
	var unblocked atomic.Int64
	time.AfterFunc(1200*time.Millisecond, func() {
		unblocked.Store(time.Now().UnixNano())
		relay.blocked.Store(false)
	})
	var wg sync.WaitGroup
	var during, after, afterOK atomic.Int64
	var firstErr atomic.Value
	for i := 0; i < n; i++ {
		time.Sleep(40 * time.Millisecond)
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			blocked := unblocked.Load() == 0
			err := echoSession(client, 4*time.Second, 1<<10, i)
			switch {
			case blocked && err == nil:
				during.Add(1)
			case !blocked:
				after.Add(1)
				if err == nil {
					afterOK.Add(1)
				} else {
					firstErr.CompareAndSwap(nil, err)
				}
			}
		}(i)
	}
	wg.Wait()
	if after.Load() == 0 {
		t.Fatal("no session started after unblock")
	}
	if afterOK.Load() != after.Load() {
		t.Fatalf("%d of %d sessions started after unblock failed: %v", after.Load()-afterOK.Load(), after.Load(), firstErr.Load())
	}
	if during.Load() == 0 {
		t.Fatal("no session started during the block got the new connection")
	}
	if got := relay.peak.Load(); got > 6 {
		t.Fatalf("%d sockets open at once, want a few", got)
	}
	t.Logf("started during block and passed: %d; after unblock: %d of %d; connections %d", during.Load(), afterOK.Load(), after.Load(), relay.accepted.Load())
}

// A block after the ClientHello, sessions coming without a break, real bounds:
// a session waits 5 s, and the handshake takes 250 ms rather than being
// instant. At the start comes a burst that itself starts the hung attempts:
// its sessions start together with them and must connect over the next ones
// rather than give up together with the hung ones. Under the block one attempt
// hangs per transport; after the block is lifted, sessions started later pass.
func TestCoalesceDialsStandRecoveryUnderLoad(t *testing.T) {
	leakCheck(t)
	// Lifting at 2 s falls just before the hung attempts are replaced (the
	// best phase), at 2.4 s right after it (the worst: we wait for the next
	// replacement).
	for _, block := range []time.Duration{2 * time.Second, 2400 * time.Millisecond} {
		t.Run(block.String(), func(t *testing.T) { standRecoveryUnderLoad(t, block) })
	}
}

func standRecoveryUnderLoad(t *testing.T, block time.Duration) {
	const xmux = 3
	const total = 9 * time.Second
	relay := newStandRelay(t, standServer(t, "stream-one"))
	relay.delay.Store(int64(250 * time.Millisecond))
	client := standClient(t, relay.addr(), "stream-one", &ReuseConfig{MaxConnections: fmt.Sprint(xmux)}, nil)
	relay.blocked.Store(true)
	time.AfterFunc(block, func() { relay.blocked.Store(false) })

	type result struct {
		start, end time.Duration
		ok, burst  bool
	}
	var mu sync.Mutex
	var all []result
	var wg sync.WaitGroup
	begin := time.Now()
	run := func(i int, burst bool) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s := time.Since(begin)
			err := echoSession(client, 5*time.Second, 1<<10, i)
			mu.Lock()
			all = append(all, result{s, time.Since(begin), err == nil, burst})
			mu.Unlock()
		}()
	}
	for i := 0; i < 32; i++ {
		run(i, true)
	}
	for i := 32; time.Since(begin) < total; i++ {
		time.Sleep(40 * time.Millisecond)
		run(i, false)
	}
	wg.Wait()

	firstOK := time.Duration(-1)
	var burstOK, during, duringOK, after, afterFailed int
	for _, r := range all {
		if r.ok && (firstOK < 0 || r.end < firstOK) {
			firstOK = r.end
		}
		switch {
		case r.burst:
			if r.ok {
				burstOK++
			}
		case r.start < block:
			during++
			if r.ok {
				duringOK++
			}
		default:
			after++
			if !r.ok {
				afterFailed++
			}
		}
	}
	t.Logf("burst passed %d of 32; started during block passed %d of %d; after unblock failed %d of %d; first success %v after unblock; accepted %d, peak %d",
		burstOK, duringOK, during, afterFailed, after, (firstOK - block).Round(100*time.Millisecond), relay.accepted.Load(), relay.peak.Load())
	if burstOK != 32 {
		t.Fatalf("burst that started the hanging attempts: %d of 32 passed", burstOK)
	}
	if afterFailed > 0 {
		t.Fatalf("%d of %d sessions started after unblock failed", afterFailed, after)
	}
	// In the worst phase the path opens with the next replacement of the
	// attempt: 2 s plus the handshake. The bound is a number rather than taken
	// from the bound in the code: an attempt living longer would keep a working
	// path closed even after the block is lifted.
	if got := firstOK - block; got > 3*time.Second {
		t.Fatalf("first session passed %v after unblock, want within 3s", got)
	}
	// Hung attempts replace each other rather than pile up: per transport, one
	// hung attempt and one working connection while the relay notices the
	// close.
	if got := relay.peak.Load(); got > 2*xmux {
		t.Fatalf("%d sockets open at once, want hanging attempts one at a time per transport", got)
	}
}

// One frozen flow on a working path: the transport's first handshake hung,
// the next one would pass at once. The burst waits no longer than the attempt
// bound and passes in full, and the transport has one hung handshake.
func TestCoalesceDialsStandFrozenHandshake(t *testing.T) {
	leakCheck(t)
	relay := newStandRelay(t, standServer(t, "stream-one"))
	relay.delay.Store(int64(100 * time.Millisecond))
	relay.freeze.Store(1)
	client := standClient(t, relay.addr(), "stream-one", &ReuseConfig{MaxConnections: "1"}, nil)
	start := time.Now()
	failed, err := sessions(client, 30, 5*time.Second, 1<<10)
	took := time.Since(start)
	t.Logf("burst of 30 behind a frozen handshake: took %v, failed %d, accepted %d, peak %d", took.Round(10*time.Millisecond), failed, relay.accepted.Load(), relay.peak.Load())
	if failed != 0 {
		t.Fatalf("%d of 30 sessions failed: %v", failed, err)
	}
	if took > 3*time.Second {
		t.Fatalf("burst behind one frozen handshake took %v", took)
	}
	if got := relay.accepted.Load(); got != 2 {
		t.Fatalf("%d connections, want the frozen one and its replacement", got)
	}
}

// A cold burst on three transports: TCP comes up at once, and the handshake is
// slow. The coalescing keeps one connection per transport at any handshake
// speed: there is no second ClientHello while the first one is going.
func TestCoalesceDialsStandSlowHandshakeBurst(t *testing.T) {
	leakCheck(t)
	for _, delay := range []time.Duration{400 * time.Millisecond, 700 * time.Millisecond} {
		upstream := standServer(t, "stream-one")
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		var accepted atomic.Int64
		var conns sync.WaitGroup
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				accepted.Add(1)
				conns.Add(1)
				go func() {
					defer conns.Done()
					defer c.Close()
					time.Sleep(delay)
					u, err := net.Dial("tcp", upstream)
					if err != nil {
						return
					}
					defer u.Close()
					go func() { io.Copy(u, c); u.Close() }()
					io.Copy(c, u)
				}()
			}
		}()
		client := standClient(t, ln.Addr().String(), "stream-one", &ReuseConfig{MaxConnections: "3"}, nil)
		if failed, err := sessions(client, 16, 5*time.Second, 1<<10); failed != 0 {
			t.Fatalf("handshake %v: %d of 16 sessions failed: %v", delay, failed, err)
		}
		if got := accepted.Load(); got != 3 {
			t.Fatalf("handshake %v: %d connections for 16 sessions on 3 transports, want 3", delay, got)
		}
		client.Close()
		ln.Close()
		conns.Wait()
	}
}
