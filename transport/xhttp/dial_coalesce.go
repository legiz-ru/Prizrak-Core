package xhttp

import (
	"context"
	"errors"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/http"
	"github.com/metacubex/http/httptrace"
)

// Dial coalescing for the HTTP/2 transport of XHTTP, ported from
// Medium1992/mihomo-proxy-ros (core_patches/xhttp_dial, 6e96723).
//
// Since the client runs on net/http.Transport (MetaCubeX/mihomo bb2f57b0),
// every request that finds no ready connection starts a dial of its own: for
// HTTP/1 that is how net/http is meant to work ("late binding"). For h2 it
// means that a cold pool, or a handshake hung after the ClientHello, costs a
// TCP connection per session, and max-connections in reuse-settings bounds the
// number of transports but not the sockets under them. The old
// http2.Transport coalesced dials itself. So does x/net after golang/go#81646
// (CL 845005), and the design follows it: the first dial leads, the others
// wait for it and leave as soon as their request has a connection from the
// pool. An address gets one attempt at a time, and one connection per
// transport holds at any handshake speed.
//
// Two handshakes to an address are never on the wire at once: while an
// attempt hangs there is no second ClientHello; a hung attempt is aborted
// (coalescedTCPTimeout, coalescedAttemptTimeout), and the next one is started
// by whoever still needs a connection, like a person pressing "reload" on a
// hung page. A slow but live attempt is not aborted: the handshake bound grows
// with the time TCP took, and the attempt goes on while the server keeps
// sending something. A backup dial happens only before TCP is up, as in Chrome
// and Firefox.
//
// Unlike x/net:
//   - a dial nobody waits for any more is aborted: on this path net/http would
//     keep a hung handshake going, and new sessions after a block is lifted
//     would wait for it instead of dialing again;
//   - a successful leader keeps its place for another coalescedDialRetry: a
//     request that comes while net/http is setting up h2 and has not put the
//     connection in the pool yet would otherwise dial on its own;
//   - a repeated search for a connection by the same request (the connection
//     did not take it) does not wait behind a successful leader but dials at
//     once;
//   - a leader aborted by its deadline does not hand its error to the
//     followers: the first of them dials itself, the others queue behind it,
//     while their sessions still have time. A refusal (a reset, a closed port,
//     a TLS error) goes to everyone, as in x/net: on a refusing path that is
//     one dial rather than a dial per follower;
//   - if the leader's TCP is not up within coalescedBackupAfter, one backup
//     dial starts.
//
// This replaces the MaxConnsPerHost 1 that Prizrak-Core set on the h2
// transport before. That also let one dial go at a time, but every request
// waited behind a dial with no deadline, so a handshake hung after the
// ClientHello held new sessions until it failed by itself.

// coalescedDialRetry is how long a follower waits for a connection after the
// leader has dialed and its RoundTrip has returned, and how long a successful
// leader keeps its place. A follower usually leaves earlier, on the GotConn of
// its request; the bound matters only when the leader's connection turned out
// unusable after the dial, and then the follower dials by itself. A
// connection that reached MAX_CONCURRENT_STREAMS is a different case: net/http
// repeats getConn for it, and that is a new dial. x/net uses 50 ms; on a weak
// router the way from handing out the connection to GotConn can take longer,
// and the follower would dial for nothing, while an extra 200 ms in the rare
// bad case costs nothing.
const coalescedDialRetry = 250 * time.Millisecond

// coalescedAttemptTimeout is how long the leader's attempt waits for the
// server to answer after TCP is up before the next attempt replaces it.
// net/http dials in a context detached from the request's cancellation, and
// the handshake on this path has no deadline: one hung after the ClientHello
// would hold every follower until the TCP timeout. The bound is both how long
// a transport stands idle on one hung handshake (a block, a frozen flow, a WAN
// change in the middle of a handshake) and how often a ClientHello goes out
// under a block: one per bound per transport. It is half a session's dial
// bound in the tunnel (C.DefaultTCPTimeout, 5 s), so that a burst that started
// a hung attempt has time to connect over the next one. An attempt is
// replaced rather than joined by a parallel one, and a slow live link would be
// cut at the same spot every time, so the bound counts from TCP being up (DNS,
// dialer-proxy and TCP itself are not in it), is at least three times this
// attempt's time to TCP, and is extended by as much again while bytes keep
// coming from the server: a block after the ClientHello is silence, while a
// slow link sends a ServerHello. All of it stays within coalescedDialTimeout.
// With TCP Fast Open dialRaw returns before the server answers: the time to
// TCP comes out near zero, the bound is exactly coalescedAttemptTimeout from
// the start, there is no backup dial, and a lost SYN is covered by the
// extension on bytes or by the next attempt.
var coalescedAttemptTimeout = 2 * time.Second

// coalescedTCPTimeout is how long an attempt waits for TCP to be up. DNS and
// the dialer-proxy chain count here, and a lost SYN is covered by the backup
// dial, so the bound is longer than coalescedAttemptTimeout.
var coalescedTCPTimeout = 3 * time.Second

// coalescedDialTimeout bounds a whole attempt, and is the same as a session's:
// nobody is left to wait for it any longer. It also bounds the dial of a
// request that bypassed the coalescing.
var coalescedDialTimeout = 5 * time.Second

// coalescedBackupAfter is when to start a backup dial if the leader's TCP is
// not up yet: the kernel resends a lost SYN only after a second. As in Chrome
// (a backup connect job after kMaxConnectRetryIntervalMs = 250, only while TCP
// is not established) and Firefox (network.http.connection-retry-timeout =
// 250, cancelled once TCP is established). Once TCP is up and the handshake is
// going, a browser sends no second ClientHello to the same server, and no
// backup starts here either.
var coalescedBackupAfter = 250 * time.Millisecond

var errCoalescedDialAbandoned = errors.New("xhttp: coalesced dial abandoned")

type dialAttemptKey struct{}

// dialLeg is one of an attempt's dials (the leader or the backup), as
// DialTCPUp sees it through the context.
type dialLeg struct {
	a    *dialAttempt
	lost atomic.Bool // TCP came up second: this dial gave way to the other
}

// dialAttempt is the course of one leader attempt: its backup dial and bounds.
type dialAttempt struct {
	start  time.Time
	tcpUp  chan struct{} // closed when the attempt's TCP (of either dial) is up
	upOnce sync.Once
	upAt   atomic.Int64 // when, in UnixNano
	read   atomic.Int64 // how many bytes the server has sent
	ended  atomic.Bool  // the attempt is over: no more need to count
}

// markUp marks TCP as up. first: this dial reached TCP first of the two (the
// leader and the backup).
func (a *dialAttempt) markUp() (first bool) {
	a.upOnce.Do(func() {
		a.upAt.Store(time.Now().UnixNano())
		close(a.tcpUp)
		first = true
	})
	return first
}

// errCoalescedSecondTCP: this dial of the attempt reached TCP second. The
// other one has started the handshake already, and there will be no second
// ClientHello to the server.
var errCoalescedSecondTCP = errors.New("xhttp: the other dial of the attempt reached TCP first")

// secondConn is the connection of a dial that reached TCP second: it is closed
// already, and wrapTLS fails on its very first write, having sent nothing.
type secondConn struct{ net.Conn }

func (secondConn) Read([]byte) (int, error)  { return 0, errCoalescedSecondTCP }
func (secondConn) Write([]byte) (int, error) { return 0, errCoalescedSecondTCP }

// DialTCPUp marks that TCP of the dial with context ctx is up and the
// handshake comes next, and returns a connection that counts the bytes the
// server sends. The DialTLSContext of the h2 transport (NewTransport) calls it
// between dialRaw and wrapTLS: from then on no backup dial starts, and the
// attempt is not aborted while the server keeps sending something. If another
// dial of the attempt has brought TCP up already (both the leader and the
// backup got there), this one is closed before starting a handshake: one
// handshake goes to the server. Outside the coalescing the connection is
// returned unchanged.
func DialTCPUp(ctx context.Context, conn net.Conn) net.Conn {
	leg, ok := ctx.Value(dialAttemptKey{}).(*dialLeg)
	if !ok {
		return conn
	}
	if !leg.a.markUp() {
		// Without TLS wrapTLS writes nothing, and the dial returns with no
		// error: the mark, not a write error, keeps dialWithBackup from
		// taking it.
		leg.lost.Store(true)
		_ = conn.Close()
		return secondConn{conn}
	}
	return &countingConn{Conn: conn, a: leg.a}
}

// countingConn counts the bytes read from the connection while the attempt
// goes on. An XHTTP connection lives for hours, so after the handshake a read
// costs one flag check. The real socket under it is reachable through
// Upstream(): that is how mihomo's wrappers and xhttp_flow's TCP_INFO find it.
type countingConn struct {
	net.Conn
	a *dialAttempt
}

func (c *countingConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 && !c.a.ended.Load() {
		c.a.read.Add(int64(n))
	}
	return n, err
}

func (c *countingConn) Upstream() any { return c.Conn }

type dialRoundTripKey struct{}

// dialRoundTrip is the state of one RoundTrip as DialTLSContext sees it:
// net/http detaches the dial's context from the request's cancellation but
// keeps its values.
type dialRoundTrip struct {
	mu       sync.Mutex
	done     bool
	getConns int           // how many times net/http looked for a connection for this RoundTrip
	donec    chan struct{} // closed when the RoundTrip has returned
	gotConnc chan struct{} // closed when the latest search for a connection has ended
}

// getConn is called by the GetConn hook at the start of every search for a
// connection (net/http searches again when an h2 connection does not take
// the request). The searches of one request come one after another, and a new
// one means the previous one has got a connection: its dial, if it still
// waits for a leader, is not needed any more.
//
// The search is marked here rather than in the dial: net/http starts a dial
// on a goroutine of its own, and the dial of an earlier search may start
// later than the dial of a newer one.
func (s *dialRoundTrip) getConn() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.gotConnc != nil {
		close(s.gotConnc)
	}
	s.gotConnc = make(chan struct{})
	s.getConns++
}

// startDial is called at the start of every dial of this RoundTrip. done:
// there is nobody to dial for, as the RoundTrip has returned or the latest
// search has got a connection already and the dial came late. retried: the
// request has had a connection already, and it did not take the request.
func (s *dialRoundTrip) startDial() (gotConnc chan struct{}, retried bool, done bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.done || s.gotConnc == nil {
		return nil, false, true
	}
	return s.gotConnc, s.getConns > 1, false
}

func (s *dialRoundTrip) gotConn() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.gotConnc != nil {
		close(s.gotConnc)
		s.gotConnc = nil
	}
}

func (s *dialRoundTrip) finish() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.done = true
	close(s.donec)
}

// leaderDial is the dial that actually goes out.
type leaderDial struct {
	dialc   chan struct{} // closed when the dial has returned; err is set by then
	err     error
	rtDonec chan struct{} // donec of the RoundTrip the dial was started for
	guard   *guardedDial
	// Under coalescingTransport.mu.
	refs int // the RoundTrips waiting for this dial
}

type coalescingTransport struct {
	*http.Transport
	mu      sync.Mutex
	leaders map[string]*leaderDial // by address, as net/http keys its pool
}

// CoalesceDials wraps a transport maker so that the dials of its HTTP/2
// transports are coalesced. Other transports pass as they are: HTTP/1.1 is
// meant to have a connection per request, and http3.Transport coalesces its
// dials itself.
func CoalesceDials(mk TransportMaker) TransportMaker {
	if mk == nil {
		return nil
	}
	return func() http.RoundTripper {
		rt := mk()
		t, ok := rt.(*http.Transport)
		if !ok || t.DialTLSContext == nil || t.Protocols == nil || !t.Protocols.UnencryptedHTTP2() {
			return rt
		}
		c := &coalescingTransport{Transport: t}
		dial := t.DialTLSContext
		t.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return c.dial(ctx, dial, network, addr)
		}
		return c
	}
}

func (c *coalescingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	rt := &dialRoundTrip{donec: make(chan struct{})}
	defer rt.finish()
	ctx := context.WithValue(req.Context(), dialRoundTripKey{}, rt)
	// WithClientTrace adds hooks to the trace already there rather than
	// replacing it: the XHTTP client's own GotConn is still called.
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		GetConn: func(string) { rt.getConn() },
		GotConn: func(httptrace.GotConnInfo) { rt.gotConn() },
	})
	return c.Transport.RoundTrip(req.WithContext(ctx))
}

func (c *coalescingTransport) dial(ctx context.Context, dial func(context.Context, string, string) (net.Conn, error), network, addr string) (net.Conn, error) {
	rt, _ := ctx.Value(dialRoundTripKey{}).(*dialRoundTrip)
	if rt == nil {
		// The request did not come through the wrapper's RoundTrip:
		// there is nothing to coalesce with.
		return boundedDial(ctx, dial, network, addr)
	}
	gotConnc, retried, done := rt.startDial()
	if done {
		return nil, errCoalescedDialAbandoned
	}
	for {
		c.mu.Lock()
		l := c.leaders[addr]
		if l != nil && retried && l.succeeded() {
			// This request has had the leader's connection already and
			// the connection did not take it (MAX_CONCURRENT_STREAMS):
			// waiting for it again is pointless, a new one is needed.
			delete(c.leaders, addr)
			l = nil
		}
		if l == nil {
			g, gctx := newGuardedDial(ctx)
			l = &leaderDial{dialc: make(chan struct{}), rtDonec: rt.donec, guard: g, refs: 1}
			if c.leaders == nil {
				c.leaders = make(map[string]*leaderDial)
			}
			c.leaders[addr] = l
			c.mu.Unlock()
			conn, err := c.lead(gctx, l, rt, dial, network, addr)
			if !errors.Is(err, os.ErrDeadlineExceeded) || !stillWaiting(ctx, rt, gotConnc) {
				return conn, err
			}
			// Our attempt hung and was aborted by its deadline, and the
			// session still waits: start the next one, unless one of the
			// followers has started it already.
			continue
		}
		l.refs++
		c.mu.Unlock()
		conn, err, again := c.follow(ctx, l, rt, gotConnc, addr)
		if !again {
			return conn, err
		}
		// The successful leader's connection did not come to us, or the
		// leader was aborted by its deadline: on the next round we lead,
		// unless another follower has taken the place already, and then we
		// queue behind it.
		c.unlead(l, addr)
	}
}

// stillWaiting reports whether this search still needs a connection: the
// RoundTrip has not returned, the search has not got a connection, and the
// dial's context is alive.
func stillWaiting(ctx context.Context, rt *dialRoundTrip, gotConnc chan struct{}) bool {
	select {
	case <-rt.donec:
		return false
	case <-gotConnc:
		return false
	case <-ctx.Done():
		return false
	default:
		return true
	}
}

// follow waits for the leader l. again: the leader has dialed and our request
// never got the connection, or the leader was aborted by its deadline; it is
// time to dial ourselves.
func (c *coalescingTransport) follow(ctx context.Context, l *leaderDial, rt *dialRoundTrip, gotConnc chan struct{}, addr string) (conn net.Conn, err error, again bool) {
	defer c.release(l, addr)
	dialc, rtDonec := l.dialc, l.rtDonec
	var retry <-chan time.Time
	for {
		if dialc == nil && rtDonec == nil && retry == nil {
			// The leader has dialed and its RoundTrip has returned, and
			// our request has no connection. Either one is about to come,
			// or something is wrong with the leader's connection; wait a
			// little and dial ourselves.
			retry = time.After(coalescedDialRetry)
		}
		select {
		case <-dialc:
			if l.err != nil {
				if errors.Is(l.err, os.ErrDeadlineExceeded) || errors.Is(l.err, errCoalescedDialAbandoned) {
					// The attempt hung and was aborted by its deadline, or
					// it was aborted because those waiting for it left and
					// we came while it was closing. Our session still
					// waits: we start the next one ourselves, like "reload"
					// on a hung page.
					return nil, nil, true
				}
				return nil, l.err, false
			}
			dialc = nil
		case <-rtDonec:
			rtDonec = nil
		case <-retry:
			return nil, nil, true
		case <-rt.donec:
			return nil, errCoalescedDialAbandoned, false
		case <-gotConnc:
			// The request has a connection, it needs this dial no more.
			return nil, errCoalescedDialAbandoned, false
		case <-ctx.Done():
			return nil, ctx.Err(), false
		}
	}
}

func (c *coalescingTransport) lead(ctx context.Context, l *leaderDial, rt *dialRoundTrip, dial func(context.Context, string, string) (net.Conn, error), network, addr string) (net.Conn, error) {
	// The leader stops waiting for its dial when its RoundTrip returns.
	stop := make(chan struct{})
	go func() {
		select {
		case <-rt.donec:
			c.release(l, addr)
		case <-stop:
		}
	}()
	a := &dialAttempt{start: time.Now(), tcpUp: make(chan struct{})}
	watched := make(chan struct{})
	go watchAttempt(l.guard, a, coalescedTCPTimeout, coalescedAttemptTimeout, watched)
	conn, err := l.guard.run(ctx, coalescedDialTimeout, func(ctx context.Context, network, addr string) (net.Conn, error) {
		return dialWithBackup(ctx, a, dial, network, addr)
	}, network, addr)
	a.ended.Store(true)
	close(watched)
	close(stop)

	if err != nil {
		// Take the leader down first, then wake the followers: the next
		// request must find the place empty and dial again.
		c.unlead(l, addr)
		l.err = err
		close(l.dialc)
		return conn, err
	}
	close(l.dialc)
	// A successful leader keeps its place for another coalescedDialRetry:
	// net/http puts the connection in the pool only after the dial has
	// returned and h2 is set up, and gives no signal for it (the leader's
	// GotConn may come earlier). A request arriving in that window finds no
	// pooled connection yet; with the leader gone it would dial by itself,
	// while this way it waits for the leader's connection and gets it from
	// the pool.
	time.AfterFunc(coalescedDialRetry, func() { c.unlead(l, addr) })
	return conn, nil
}

// watchAttempt aborts the attempt a once it has hung: TCP is not up within
// tcpTimeout (coalescedTCPTimeout), or the server stays silent for longer than
// the handshake bound (coalescedAttemptTimeout, given as attemptTimeout). The
// coalescedDialTimeout bound is set by the guard itself. The bounds are passed
// in when the attempt starts rather than read on the goroutine, as is the
// guard's.
func watchAttempt(g *guardedDial, a *dialAttempt, tcpTimeout, attemptTimeout time.Duration, done <-chan struct{}) {
	wait := func(d time.Duration) bool {
		t := time.NewTimer(d)
		defer t.Stop()
		select {
		case <-t.C:
			return true
		case <-done:
			return false
		}
	}
	tcp := time.NewTimer(tcpTimeout)
	select {
	case <-a.tcpUp:
		tcp.Stop()
	case <-tcp.C:
		g.abort(os.ErrDeadlineExceeded)
		return
	case <-done:
		tcp.Stop()
		return
	}
	bound := attemptTimeout
	if d := 3 * time.Duration(a.upAt.Load()-a.start.UnixNano()); d > bound {
		bound = d
	}
	var read int64
	for wait(bound) {
		n := a.read.Load()
		if n == read {
			// Not a byte from the server over the whole bound: the
			// handshake has hung.
			g.abort(os.ErrDeadlineExceeded)
			return
		}
		read = n
	}
}

// dialWithBackup dials, and if TCP is not up within coalescedBackupAfter,
// starts one backup dial. The first to succeed wins; the other is aborted, and
// its connection, if it made one, is closed. The winner's context is not
// cancelled: connection wrappers may tie their lifetime to it.
func dialWithBackup(ctx context.Context, a *dialAttempt, dial func(context.Context, string, string) (net.Conn, error), network, addr string) (net.Conn, error) {
	type result struct {
		conn net.Conn
		err  error
		idx  int
	}
	results := make(chan result, 2)
	var cancels [2]context.CancelFunc
	var legs [2]dialLeg
	start := func(idx int) {
		legs[idx].a = a
		actx, cancel := context.WithCancel(context.WithValue(ctx, dialAttemptKey{}, &legs[idx]))
		cancels[idx] = cancel
		go func() {
			conn, err := dial(actx, network, addr)
			results <- result{conn, err, idx}
		}()
	}
	start(0)
	backup := time.NewTimer(coalescedBackupAfter)
	defer backup.Stop()
	backupC := backup.C
	running := 1
	var firstErr error
	for running > 0 {
		select {
		case <-backupC:
			backupC = nil
			select {
			case <-a.tcpUp:
			default:
				running++
				start(1)
			}
		case r := <-results:
			running--
			if r.err == nil && legs[r.idx].lost.Load() {
				// The dial that gave TCP way returned "successfully"
				// (XHTTP without TLS): its connection is closed and of no
				// use to anyone.
				if r.conn != nil {
					_ = r.conn.Close()
				}
				r.conn, r.err = nil, errCoalescedSecondTCP
			}
			if r.err == nil {
				if running > 0 {
					// The loser is aborted; its connection, if it does
					// connect after all, is of no use to anyone.
					cancels[1-r.idx]()
					go func() {
						if l := <-results; l.conn != nil {
							_ = l.conn.Close()
						}
					}()
				}
				return r.conn, nil
			}
			cancels[r.idx]()
			// The error of a dial that gave TCP way to the other says
			// nothing about the path: the attempt reports the error of the
			// one that went further.
			if firstErr == nil || errors.Is(firstErr, errCoalescedSecondTCP) {
				firstErr = r.err
			}
		}
	}
	return nil, firstErr
}

// succeeded reports whether the leader's dial has ended successfully.
func (l *leaderDial) succeeded() bool {
	select {
	case <-l.dialc:
		return l.err == nil
	default:
		return false
	}
}

// unlead frees the leader's place if l still holds it.
func (c *coalescingTransport) unlead(l *leaderDial, addr string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.leaders[addr] == l {
		delete(c.leaders, addr)
	}
}

// release takes one waiting RoundTrip off l. When the last one has left and
// the dial is still going, it is aborted: net/http keeps a dial for future
// requests, but a hung handshake only stands in their way. The leader's place
// is freed when the abort has finished rather than at once: otherwise the next
// request would start a handshake while the previous one is still closing. A
// request that comes at that moment queues behind the aborted dial and dials
// right after it.
func (c *coalescingTransport) release(l *leaderDial, addr string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if l.refs--; l.refs > 0 {
		return
	}
	l.guard.abort(errCoalescedDialAbandoned)
}

// guardedDial is a dial that can be aborted by its deadline or because nobody
// needs it any more. Its context is cancelled only while the dial is going:
// after a successful dial it stays alive, as the context net/http passes here
// does, in case connection wrappers tie their lifetime to it.
type guardedDial struct {
	mu     sync.Mutex
	cancel context.CancelFunc
	done   bool
	reason error
}

func newGuardedDial(ctx context.Context) (*guardedDial, context.Context) {
	ctx, cancel := context.WithCancel(ctx)
	return &guardedDial{cancel: cancel}, ctx
}

func (g *guardedDial) abort(reason error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.done || g.reason != nil {
		return
	}
	g.reason = reason
	g.cancel()
}

func (g *guardedDial) run(ctx context.Context, timeout time.Duration, dial func(context.Context, string, string) (net.Conn, error), network, addr string) (net.Conn, error) {
	timer := time.AfterFunc(timeout, func() { g.abort(os.ErrDeadlineExceeded) })
	conn, err := dial(ctx, network, addr)
	timer.Stop()
	g.mu.Lock()
	g.done = true
	reason := g.reason
	g.mu.Unlock()
	if reason == nil {
		return conn, err
	}
	// The dial was aborted. Even if it managed to return a connection, its
	// context is cancelled already and the connection cannot be relied on.
	// The error is the reason for the abort, not whatever the dial answered
	// the cancellation with: by it the followers tell a hung attempt from a
	// refusal.
	if conn != nil {
		_ = conn.Close()
	}
	return nil, reason
}

// boundedDial bounds a dial by coalescedDialTimeout.
func boundedDial(ctx context.Context, dial func(context.Context, string, string) (net.Conn, error), network, addr string) (net.Conn, error) {
	g, ctx := newGuardedDial(ctx)
	return g.run(ctx, coalescedDialTimeout, dial, network, addr)
}
