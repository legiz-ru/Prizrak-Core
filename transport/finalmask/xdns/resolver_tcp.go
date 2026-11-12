package xdns

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	stdhttptrace "net/http/httptrace"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/common/contextutils"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/transport/finalmask"

	"github.com/metacubex/http/httptrace"
)

// maxMessage is the longest DNS message a resolver passes, the 4 KiB of
// Xray's buffers.
const maxMessage = 4096

// warnInterval spaces out the warnings of a resolver whose queries keep
// failing: a tunnel sends many.
const warnInterval = 10 * time.Second

// dialTimeout bounds a dial of a tcp resolver, and the dial and TLS
// handshake of a DoH connection: a resolver that does not answer the SYN
// would otherwise hold its worker, and the Sends behind it, until the
// system gives up.
const dialTimeout = 15 * time.Second

// dialValues is the context of a resolver's dials: the values of the
// caller's, which the proxy's dialer may read, but not its cancellation (the
// client outlives the dial that made it) and not its HTTP trace hooks. A
// client made while XHTTP dials over HTTP/3 has that request's hooks in it,
// which no dial of the resolvers must call.
type dialValues struct {
	context.Context
}

func (c dialValues) Value(key any) any {
	v := c.Context.Value(key)
	switch v.(type) {
	case *httptrace.ClientTrace, *stdhttptrace.ClientTrace:
		return nil
	}
	return v
}

func dialContext(ctx context.Context) context.Context {
	return dialValues{contextutils.WithoutCancel(ctx)}
}

var errResolverClosed = errors.New("xdns: resolver closed")

// The pause of a resolver whose connections keep failing: backoffMin after
// the first failure, doubling up to backoffMax.
const (
	backoffMin = time.Second
	backoffMax = 30 * time.Second
)

// dialBackoff pauses a tcp or https resolver whose dials keep failing (a
// resolver that is down, a TLS that never passes): while it pauses, the
// queries the workers take are dropped, as during a 429's Retry-After.
// Without it every query of the tunnel dials at once, and a phone runs out
// of local ports within a minute (Xray-core has no such pause).
type dialBackoff struct {
	mu       sync.Mutex
	until    time.Time
	failures int
}

// cooling reports whether the resolver pauses now.
func (b *dialBackoff) cooling() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return time.Now().Before(b.until)
}

// fail notes a failed dial; the failures of dials in flight when the pause
// began do not lengthen it.
func (b *dialBackoff) fail() {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	if now.Before(b.until) {
		return
	}
	if b.failures < 6 {
		b.failures++
	}
	wait := backoffMin << (b.failures - 1)
	if wait > backoffMax {
		wait = backoffMax
	}
	b.until = now.Add(wait)
}

// ok notes a connection that worked: the next failure pauses briefly again.
func (b *dialBackoff) ok() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.failures = 0
}

// workQueue hands the queries of a tcp or https resolver to its workers and
// their answers to Read, as Xray's sendCh and readCh: Send waits for a free
// worker.
type workQueue struct {
	readCh  chan []byte
	sendCh  chan []byte
	closeCh chan struct{}
	wg      sync.WaitGroup

	udpAddr  atomic.Pointer[net.UDPAddr]
	lastWarn atomic.Int64
	backoff  dialBackoff
}

func (q *workQueue) init() {
	q.readCh = make(chan []byte)
	q.sendCh = make(chan []byte)
	q.closeCh = make(chan struct{})
	q.udpAddr.Store(&net.UDPAddr{IP: net.IPv4zero})
}

func (q *workQueue) closed() bool {
	select {
	case <-q.closeCh:
		return true
	default:
		return false
	}
}

// next is the query a worker takes; false once the resolver is closed.
func (q *workQueue) next() ([]byte, bool) {
	select {
	case <-q.closeCh:
		return nil, false
	default:
	}
	select {
	case <-q.closeCh:
		return nil, false
	case p := <-q.sendCh:
		return p, true
	}
}

// deliver passes an answer, a buffer of pool4K, to Read.
func (q *workQueue) deliver(p []byte) {
	select {
	case <-q.closeCh:
		pool4K.Put(p[:cap(p)])
	case q.readCh <- p:
	}
}

// setAddr notes the server of the connection dialed last, the address the
// answers are reported from.
func (q *workQueue) setAddr(addr net.Addr, fallback string) {
	switch v := addr.(type) {
	case *net.TCPAddr:
		q.udpAddr.Store(&net.UDPAddr{IP: v.IP, Port: v.Port, Zone: v.Zone})
	case *net.UDPAddr:
		q.udpAddr.Store(v)
	default:
		if udpAddr, err := net.ResolveUDPAddr("udp", fallback); err == nil {
			q.udpAddr.Store(udpAddr)
		}
	}
}

func (q *workQueue) warn(format string, args ...any) {
	if q.closed() {
		return
	}
	now := time.Now().UnixNano()
	last := q.lastWarn.Load()
	if now-last < int64(warnInterval) || !q.lastWarn.CompareAndSwap(last, now) {
		log.Debugln("[finalmask] xdns: "+format, args...)
		return
	}
	log.Warnln("[finalmask] xdns: "+format, args...)
}

func (q *workQueue) Addr() *net.UDPAddr {
	return q.udpAddr.Load()
}

func (q *workQueue) Read(p []byte) (n int, err error) {
	packet, ok := <-q.readCh
	if ok {
		n = copy(p, packet)
		pool4K.Put(packet[:cap(packet)])
		return n, nil
	}
	return 0, io.ErrClosedPipe
}

// Send waits for a worker to take a copy of p; after Close it drops p.
func (q *workQueue) Send(p []byte) {
	if q.closed() {
		return
	}
	b := make([]byte, len(p))
	copy(b, p)
	select {
	case <-q.closeCh:
	case q.sendCh <- b:
	}
}

// TCPResolver is DNS over TCP as in Xray-core since 14df0738: up to worker
// queries in flight, each worker with a connection of its own that is dialed
// when the worker first needs it and kept for its next query. A query waits
// for its answer before the connection takes another; a failure closes the
// connection and the worker's next query dials again.
type TCPResolver struct {
	workQueue

	ctx    context.Context
	cancel context.CancelFunc
	addr   string
	dialer *finalmask.Dialer

	mu    sync.Mutex
	conns map[net.Conn]struct{}
}

func NewTCPResolver(ctx context.Context, config ResolverConfig, dialer *finalmask.Dialer) (Resolver, error) {
	if config.Worker < 1 {
		return nil, fmt.Errorf("xdns: tcp resolver %s needs at least one worker", config.Addr)
	}
	ctx, cancel := context.WithCancel(dialContext(ctx))
	r := &TCPResolver{
		ctx:    ctx,
		cancel: cancel,
		addr:   config.Addr,
		dialer: dialer,
		conns:  map[net.Conn]struct{}{},
	}
	r.init()
	for i := 0; i < config.Worker; i++ {
		r.wg.Add(1)
		go r.worker()
	}
	return r, nil
}

func (r *TCPResolver) worker() {
	defer r.wg.Done()
	var conn net.Conn
	var frame []byte
	for {
		p, ok := r.next()
		if !ok {
			break
		}
		// A resolver whose dials keep failing pauses: the query is dropped.
		if conn == nil && r.backoff.cooling() {
			continue
		}
		if err := r.do(&conn, &frame, p); err != nil {
			r.warn("tcp resolver %s: %v", r.addr, err)
		}
	}
	if conn != nil {
		r.drop(conn)
	}
}

// track adds a dialed connection to those Close closes; false when the
// resolver is closed already.
func (r *TCPResolver) track(conn net.Conn) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed() {
		return false
	}
	r.conns[conn] = struct{}{}
	return true
}

func (r *TCPResolver) drop(conn net.Conn) {
	r.mu.Lock()
	delete(r.conns, conn)
	r.mu.Unlock()
	_ = conn.Close()
}

// do sends p on the worker's connection, dialing it if there is none, and
// waits for the answer.
func (r *TCPResolver) do(conn *net.Conn, frame *[]byte, p []byte) error {
	if len(p) > maxMessage {
		return fmt.Errorf("query of %d bytes is too long", len(p))
	}
	if *conn == nil {
		ctx, cancel := context.WithTimeout(r.ctx, dialTimeout)
		c, err := r.dialer.DialTCP(ctx, r.addr)
		cancel()
		if err != nil {
			if !r.closed() {
				r.backoff.fail()
			}
			return err
		}
		r.backoff.ok()
		if !r.track(c) {
			_ = c.Close()
			return errResolverClosed
		}
		r.setAddr(c.RemoteAddr(), r.addr)
		*conn = c
	}
	c := *conn
	// DNS over TCP prefixes each message with its length (RFC 1035 4.2.2),
	// in one write as RFC 7766 8 asks.
	if *frame == nil {
		*frame = make([]byte, 2+maxMessage)
	}
	f := (*frame)[:2+len(p)]
	binary.BigEndian.PutUint16(f, uint16(len(p)))
	copy(f[2:], p)
	if _, err := c.Write(f); err != nil {
		r.drop(c)
		*conn = nil
		return err
	}
	b := pool4K.Get().([]byte)
	n, err := readTCPMessage(c, b)
	if err != nil {
		pool4K.Put(b[:cap(b)])
		r.drop(c)
		*conn = nil
		return err
	}
	r.deliver(b[:n])
	return nil
}

// readTCPMessage reads one length-prefixed message into b, which holds
// maxMessage bytes.
func readTCPMessage(conn net.Conn, b []byte) (int, error) {
	if _, err := io.ReadFull(conn, b[:2]); err != nil {
		return 0, err
	}
	n := int(binary.BigEndian.Uint16(b[:2]))
	if n == 0 || n > maxMessage {
		return 0, fmt.Errorf("answer length %d", n)
	}
	if _, err := io.ReadFull(conn, b[:n]); err != nil {
		return 0, err
	}
	return n, nil
}

// Close stops the workers: a dial is canceled and the connections are
// closed, so a worker waiting on an answer that never comes ends as well.
func (r *TCPResolver) Close() {
	r.mu.Lock()
	if r.closed() {
		r.mu.Unlock()
		return
	}
	close(r.closeCh)
	conns := make([]net.Conn, 0, len(r.conns))
	for conn := range r.conns {
		conns = append(conns, conn)
	}
	r.mu.Unlock()
	r.cancel()
	for _, conn := range conns {
		_ = conn.Close()
	}
	r.wg.Wait()
	close(r.readCh)
}
