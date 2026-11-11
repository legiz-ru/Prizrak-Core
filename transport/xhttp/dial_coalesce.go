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
//   - a repeated search for a connection by the same request (the connection
//     did not take it) does not wait behind a successful leader but dials at
//     once;
//   - nobody waits behind a leader that has been dialing for longer than
//     coalescedDialStale: a new request or one of the followers dials itself;
//   - if the leader has been dialing for twice as long as usual for this
//     client, one of the followers starts a backup dial (coalescedHedgeMin).
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

// coalescedDialStale is longer than a handshake takes on a working path, so a
// leader dialing for longer has most likely hung: a block after the
// ClientHello remembers the flow, and lifting the block will not revive it.
// Nobody waits behind such a leader: the first follower to notice the bound
// dials itself, the others queue behind it, and a request arriving later
// notices the bound at once. Otherwise a page's burst started during a block
// would hold on to the hung dial until coalescedDialTimeout, and sessions that
// came after the block was lifted would wait for it. A successful new dial
// puts its connection in the pool, where those who waited for the old leader
// get it too. While the path stays blocked, an address gets at most one new
// dial per coalescedDialStale, and each takes up one follower. The bound is
// above a REALITY handshake on a slow mobile link (0.6-0.9 s): a smaller one
// would make extra dials there.
var coalescedDialStale = time.Second

// coalescedHedgeMin is the lower bound of the backup dial's deadline. The
// kernel resends a lost SYN or ClientHello only after a second, and the whole
// cold burst would wait for that resend, while stock carries on over its
// other dials. So if the leader has been dialing for twice the smoothed
// handshake time (dialHistory), one of the followers starts a backup dial and
// the others queue behind it; net/http hands the connection of whichever
// lands first to everyone. The lower bound keeps noise on a fast link from
// making extra dials; the upper one is coalescedDialStale, past which that
// rule takes over. Only an ordinary leader gets a backup dial: the backup
// itself and leaders started after coalescedDialStale do not, so at most two
// dials go at once, and a blocked path still sees at most one new dial per
// coalescedDialStale. With no history (the client's first dial) the deadline
// cannot be guessed, and there is no backup dial.
var coalescedHedgeMin = 250 * time.Millisecond

var errCoalescedDialAbandoned = errors.New("xhttp: coalesced dial abandoned")

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
	started time.Time     // when the dial started
	// hedgeable: an ordinary leader, which gets a backup dial. The backup
	// itself and leaders started after leaving an earlier one do not.
	hedgeable bool
	guard     *guardedDial
	refs      int // under coalescingTransport.mu: the RoundTrips waiting for this dial
}

type coalescingTransport struct {
	*http.Transport
	hist    *dialHistory
	mu      sync.Mutex
	leaders map[string]*leaderDial // by address, as net/http keys its pool
}

// dialHistory is the smoothed time of a successful dial per address, shared
// by all transports of one maker, that is, one XHTTP client and one direction.
// A cold burst is exactly a set of fresh transports, and a measurement kept
// inside a transport would never build up. It cannot be global either: the
// address is the host from the URL, and proxies behind one CDN host on
// different servers would mix their measurements. The smoothing is TCP's SRTT
// one (weight 1/8): a single slow dial, say after a network change, does not
// stretch the deadline at once, and a new network is caught up with in a few
// handshakes.
type dialHistory struct {
	mu   sync.Mutex
	srtt map[string]time.Duration
}

func (h *dialHistory) observe(addr string, d time.Duration) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.srtt == nil {
		h.srtt = make(map[string]time.Duration)
	}
	if old, ok := h.srtt[addr]; ok {
		d = old + (d-old)/8
	}
	h.srtt[addr] = d
}

// hedgeAfter is how long after the leader's dial started to start a backup
// one. ok = false: there is no history, or the deadline is not below
// coalescedDialStale.
func (h *dialHistory) hedgeAfter(addr string) (d time.Duration, ok bool) {
	if h == nil {
		return 0, false
	}
	h.mu.Lock()
	srtt, ok := h.srtt[addr]
	h.mu.Unlock()
	if !ok {
		return 0, false
	}
	d = 2 * srtt
	if d < coalescedHedgeMin {
		d = coalescedHedgeMin
	}
	return d, d < coalescedDialStale
}

// CoalesceDials wraps a transport maker so that the dials of its HTTP/2
// transports are coalesced. Other transports pass as they are: HTTP/1.1 is
// meant to have a connection per request, and http3.Transport coalesces its
// dials itself.
func CoalesceDials(mk TransportMaker) TransportMaker {
	if mk == nil {
		return nil
	}
	hist := &dialHistory{}
	return func() http.RoundTripper {
		rt := mk()
		t, ok := rt.(*http.Transport)
		if !ok || t.DialTLSContext == nil || t.Protocols == nil || !t.Protocols.UnencryptedHTTP2() {
			return rt
		}
		c := &coalescingTransport{Transport: t, hist: hist}
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
	// While this request has not left a leader, its dial is an ordinary one;
	// once it has, its dial is a backup or one after a hung leader, and it
	// gets no backup of its own.
	hedgeable := true
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
			l = &leaderDial{dialc: make(chan struct{}), rtDonec: rt.donec, started: time.Now(), hedgeable: hedgeable, guard: g, refs: 1}
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
		// The leader's connection did not come to us, the leader hung, or it
		// is time for a backup dial: take it down so that on the next round
		// we lead rather than wait for it again. If another one has replaced
		// it, we queue behind that one. The leader itself keeps dialing.
		c.unlead(l, addr)
		hedgeable = false
	}
}

// follow waits for the leader l. again: the leader has dialed and our request
// never got the connection, the leader hung, or it is time for a backup dial;
// it is time to dial ourselves.
func (c *coalescingTransport) follow(ctx context.Context, l *leaderDial, rt *dialRoundTrip, gotConnc chan struct{}, addr string) (conn net.Conn, err error, again bool) {
	defer c.release(l, addr)
	dialc, rtDonec := l.dialc, l.rtDonec
	var retry <-chan time.Time
	wait := coalescedDialStale
	if l.hedgeable {
		if d, ok := c.hist.hedgeAfter(addr); ok {
			wait = d
		}
	}
	stale := time.NewTimer(time.Until(l.started.Add(wait)))
	defer stale.Stop()
	// A channel variable rather than stale.C in the select: with go 1.20 in
	// go.mod a stopped timer may leave a value in its channel.
	staleC := stale.C
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
			staleC = nil
		case <-staleC:
			staleC = nil
			select {
			case <-l.dialc:
				// The dial ended right at the bound: handle it as usual.
			default:
				return nil, nil, true
			}
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
	c.hist.observe(addr, time.Since(l.started))
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
