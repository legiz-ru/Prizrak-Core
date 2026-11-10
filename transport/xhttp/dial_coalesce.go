package xhttp

import (
	"context"
	"errors"
	"net"
	"os"
	"sync"
	"time"

	"github.com/metacubex/http"
	"github.com/metacubex/http/httptrace"
)

// Dial coalescing for the HTTP/2 transport of XHTTP, ported from
// Medium1992/mihomo-proxy-ros (core_patches/xhttp_dial, c03d991).
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
// pool. Everyone who waited for a leader gets its error.
// Unlike x/net:
//   - a dial nobody waits for any more is aborted: on this path net/http would
//     keep a hung handshake going, and new sessions after a block is lifted
//     would wait for it instead of dialing again;
//   - a successful leader keeps its place for another coalescedDialRetry: a
//     request that comes while net/http is setting up h2 and has not put the
//     connection in the pool yet would otherwise dial on its own;
//   - a repeated getConn of the same request (the connection did not take it)
//     does not wait behind a successful leader but dials at once.
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

// coalescedDialTimeout bounds the leader's dial. net/http dials in a context
// detached from the request's cancellation, and the handshake on this path has
// no deadline: one hung after the ClientHello would hold every follower until
// the TCP timeout. The bound is the one of a session's dial in the tunnel
// (C.DefaultTCPTimeout): a leader hanging longer helps none of those who
// waited, and new sessions after a block is lifted would wait for it instead
// of dialing again.
var coalescedDialTimeout = 5 * time.Second

var errCoalescedDialAbandoned = errors.New("xhttp: coalesced dial abandoned")

type dialRoundTripKey struct{}

// dialRoundTrip is the state of one RoundTrip as DialTLSContext sees it:
// net/http detaches the dial's context from the request's cancellation but
// keeps its values.
type dialRoundTrip struct {
	mu       sync.Mutex
	done     bool
	attempts int           // how many times net/http dialed for this RoundTrip
	donec    chan struct{} // closed when the RoundTrip has returned
	gotConnc chan struct{} // closed when the request has got a connection
}

// startDial is called at the start of every dial of this RoundTrip (net/http
// repeats getConn when an h2 connection does not take the request). done:
// the RoundTrip has returned already and there is nobody to dial for.
//
// A new getConn means the previous one has got a connection, and its dial, if
// it still waits for a leader, is not needed any more: its channel is closed
// here, or it would never see GotConn and would dial for nothing.
func (s *dialRoundTrip) startDial() (gotConnc chan struct{}, retried bool, done bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.done {
		return nil, false, true
	}
	if s.gotConnc != nil {
		close(s.gotConnc)
	}
	s.gotConnc = make(chan struct{})
	s.attempts++
	return s.gotConnc, s.attempts > 1, false
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
	refs    int // under coalescingTransport.mu: the RoundTrips waiting for this dial
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
	// WithClientTrace adds a hook to the trace already there rather than
	// replacing it: the XHTTP client's own GotConn is still called.
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
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
			return c.lead(gctx, l, rt, dial, network, addr)
		}
		l.refs++
		c.mu.Unlock()

		conn, err, again := c.follow(ctx, l, rt, gotConnc, addr)
		if !again {
			return conn, err
		}
		// The leader's connection did not come to us: take the leader
		// down so that on the next round we lead rather than wait for it
		// again.
		c.unlead(l, addr)
	}
}

// follow waits for the leader l. again: the leader has dialed, and our request
// never got the connection; it is time to dial ourselves.
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
	conn, err := l.guard.run(ctx, dial, network, addr)
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
// is freed at once, and the next request dials again instead of waiting for a
// doomed dial.
func (c *coalescingTransport) release(l *leaderDial, addr string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if l.refs--; l.refs > 0 {
		return
	}
	if c.leaders[addr] == l {
		delete(c.leaders, addr)
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

func (g *guardedDial) run(ctx context.Context, dial func(context.Context, string, string) (net.Conn, error), network, addr string) (net.Conn, error) {
	timer := time.AfterFunc(coalescedDialTimeout, func() { g.abort(os.ErrDeadlineExceeded) })
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
	if conn != nil {
		_ = conn.Close()
	}
	if err == nil || errors.Is(err, context.Canceled) {
		err = reason
	}
	return nil, err
}

// boundedDial bounds a dial by coalescedDialTimeout.
func boundedDial(ctx context.Context, dial func(context.Context, string, string) (net.Conn, error), network, addr string) (net.Conn, error) {
	g, ctx := newGuardedDial(ctx)
	return g.run(ctx, dial, network, addr)
}
