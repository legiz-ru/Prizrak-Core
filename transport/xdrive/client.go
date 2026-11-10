// Ported from Xray-core v26.11.9 transport/internet/xdrive
// (https://github.com/XTLS/Xray-core), which is licensed under the Mozilla
// Public License 2.0; this file stays under MPL-2.0.
// SPDX-License-Identifier: MPL-2.0

package xdrive

import (
	"context"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/contextutils"
	tlsC "github.com/metacubex/mihomo/component/tls"
	"github.com/metacubex/mihomo/transport/xhttp"

	"github.com/metacubex/http"
	"github.com/metacubex/quic-go"
	"github.com/metacubex/quic-go/http3"
	"github.com/metacubex/tls"
)

var errStalled = newError("the request made no progress")

type serviceTransport struct {
	plain  http.RoundTripper
	secure http.RoundTripper
	stall  time.Duration
}

// RoundTrip ends a request that stands still for t.stall, with no answer that
// long after its body went out or no byte of either body, but not one that just
// runs long: a large object on a slow link takes minutes and is fine as long as
// its bytes move
func (t *serviceTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	next := t.plain
	if r.URL.Scheme == "https" {
		next = t.secure
	}

	ctx, cancel := context.WithCancelCause(r.Context())
	timer := time.AfterFunc(t.stall, func() { cancel(errStalled) })
	alive := func() { timer.Reset(t.stall) }
	end := func() {
		timer.Stop()
		cancel(nil)
	}
	r = r.WithContext(ctx)
	// the headers of chrome as with XHTTP and DoH, net/http and http3 would send
	// their own user agent after a hello of chrome
	r.Header = r.Header.Clone()
	xhttp.TryDefaultHeadersWith(r.Header, "fetch")
	if r.Body != nil && r.Body != http.NoBody {
		r.Body = &progressBody{ReadCloser: r.Body, alive: alive}
	}
	// a body sent again by the transport itself, after a GOAWAY or on a reused
	// connection that failed, moves just the same
	if getBody := r.GetBody; getBody != nil {
		r.GetBody = func() (io.ReadCloser, error) {
			body, err := getBody()
			if err != nil || body == http.NoBody {
				return body, err
			}
			return &progressBody{ReadCloser: body, alive: alive}, nil
		}
	}

	resp, err := next.RoundTrip(r)
	if err != nil {
		err = stalled(ctx, err)
		end()
		return nil, err
	}
	alive()
	resp.Body = &progressBody{ReadCloser: resp.Body, alive: alive, end: end, ctx: ctx}
	return resp, nil
}

// stalled returns errStalled for an error that the stall gave, which http2 reports
// as a plain cancel
func stalled(ctx context.Context, err error) error {
	if context.Cause(ctx) == errStalled {
		return errStalled
	}
	return err
}

type progressBody struct {
	io.ReadCloser
	alive func()
	end   func()
	// ctx is that of the request, for the body of its response
	ctx context.Context
}

func (b *progressBody) Read(p []byte) (int, error) {
	// http2 reads a request body up to 512 KiB at a time and sends it all before
	// the next read, which on a slow link could look like no progress
	n, err := b.ReadCloser.Read(p[:min(len(p), 16<<10)])
	if n > 0 {
		b.alive()
	}
	if err != nil && err != io.EOF && b.ctx != nil {
		err = stalled(b.ctx, err)
	}
	return n, err
}

func (b *progressBody) Close() error {
	err := b.ReadCloser.Close()
	if b.end != nil {
		b.end()
	}
	return err
}

// newServiceClient returns a client whose requests end after stall without
// progress, see serviceTransport.RoundTrip, and whose connections close when
// connCtx is done. Clients that share h1Hosts share which hosts answer over h1
func newServiceClient(connCtx context.Context, h1Hosts *sync.Map, dialer *Dialer, config *Config, stall time.Duration, maxConns int) *http.Client {
	if dialer == nil {
		dialer = &Dialer{}
	}
	keepAlive := xhttp.ChromeH2KeepAlivePeriod
	// h3 keeps alive only when asked to, see below
	var h3KeepAlive time.Duration
	if config != nil && config.Xmux != nil {
		switch period := config.Xmux.HKeepAlivePeriod; {
		case period > 0:
			keepAlive = time.Duration(period) * time.Second
			h3KeepAlive = keepAlive
		case period < 0:
			keepAlive = 0
		}
	}

	target := func(addr string) (string, string, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return "", "", newError("bad address: ", addr).Base(err)
		}
		to := addr
		if dialer.Address != "" {
			if dialer.Port != 0 {
				port = strconv.Itoa(dialer.Port)
			}
			to = net.JoinHostPort(dialer.Address, port)
		}
		return host, to, nil
	}

	dial := func(ctx context.Context, addr string) (net.Conn, string, error) {
		host, to, err := target(addr)
		if err != nil {
			return nil, "", err
		}
		var conn net.Conn
		if dialer.DialTCP != nil {
			conn, err = dialer.DialTCP(ctx, to)
		} else {
			conn, err = (&net.Dialer{}).DialContext(ctx, "tcp", to)
		}
		if err != nil {
			return nil, host, newError("failed to dial to dest").Base(err)
		}
		// CloseIdleConnections leaves an h2 connection open while a stream just
		// canceled has not left it yet
		stop := contextutils.AfterFunc(connCtx, func() { conn.Close() })
		return &ctxConn{Conn: conn, stop: stop}, host, nil
	}

	dialPlain := func(ctx context.Context, network, addr string) (net.Conn, error) {
		conn, _, err := dial(ctx, addr)
		return conn, err
	}

	// http.Transport picks h2 or h1 by the ALPN in the ConnectionState of the conn
	dialTLS := func(ctx context.Context, network, addr string) (net.Conn, error) {
		conn, host, err := dial(ctx, addr)
		if err != nil {
			return nil, err
		}
		// the dial outlives the request that started it, and a handshake that hangs
		// would keep the one connection of the host to itself
		ctx, cancel := context.WithTimeout(ctx, stall)
		defer cancel()
		var tlsConn net.Conn
		if dialer.WrapTLS != nil {
			tlsConn, err = dialer.WrapTLS(ctx, conn, host)
		} else {
			c := tls.Client(conn, &tls.Config{ServerName: host, NextProtos: []string{"h2", "http/1.1"}})
			err = c.HandshakeContext(ctx)
			tlsConn = c
		}
		if err != nil {
			conn.Close()
			return nil, err
		}
		return tlsStateConn(tlsConn), nil
	}

	secure := func(connsPerHost int) *http.Transport {
		return &http.Transport{
			DialTLSContext:      dialTLS,
			ForceAttemptHTTP2:   true,
			IdleConnTimeout:     xhttp.ConnIdleTimeout,
			MaxIdleConns:        maxConns,
			MaxIdleConnsPerHost: maxConns,
			MaxConnsPerHost:     connsPerHost,
			HTTP2:               &http.HTTP2Config{SendPingTimeout: keepAlive},
		}
	}

	var https http.RoundTripper = &secureTransport{h2: secure(1), h1: secure(maxConns), h1Hosts: h1Hosts}
	// no server offers h3 by ALPN over TCP, so it is used only when asked for alone
	if dialer.H3 {
		https = &http3.Transport{
			QUICConfig: &quic.Config{
				MaxIncomingStreams: -1,
				// the defaults are those of quic-go, with no keepalive unless asked for, as
				// in DoH: http3 never closes a connection that is idle or that it dropped
				// after an error, so only the idle timeout or the end of connCtx ends it
				KeepAlivePeriod: h3KeepAlive,
				MaxIdleTimeout:  xhttp.ConnIdleTimeout,
			},
			Dial: func(ctx context.Context, addr string, _ *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
				if dialer.DialQUIC == nil {
					return nil, newError("h3 is not available here")
				}
				host, to, err := target(addr)
				if err != nil {
					return nil, err
				}
				qconn, err := dialer.DialQUIC(ctx, to, host, cfg)
				if err != nil {
					return nil, err
				}
				stop := contextutils.AfterFunc(connCtx, func() { qconn.CloseWithError(quic.ApplicationErrorCode(http3.ErrCodeNoError), "") })
				contextutils.AfterFunc(qconn.Context(), func() { stop() })
				return qconn, nil
			},
		}
	}

	return &http.Client{
		Transport: &serviceTransport{
			plain: &http.Transport{
				DialContext:         dialPlain,
				IdleConnTimeout:     xhttp.ConnIdleTimeout,
				MaxIdleConns:        maxConns,
				MaxIdleConnsPerHost: maxConns,
				MaxConnsPerHost:     maxConns,
			},
			secure: https,
			stall:  stall,
		},
	}
}

// ctxConn is a connection that connCtx no longer closes once it is closed,
// so that one that ends on its own leaves nothing behind in connCtx
type ctxConn struct {
	net.Conn
	stop func() bool
}

func (c *ctxConn) Close() error {
	c.stop()
	return c.Conn.Close()
}

// utlsConn gives http.Transport the ConnectionState of a uTLS connection, which
// has a type of uTLS, for the ALPN it picks h2 or h1 by.
type utlsConn struct {
	*tlsC.UConn
}

func (c utlsConn) ConnectionState() tls.ConnectionState {
	state := c.UConn.ConnectionState()
	return tls.ConnectionState{
		HandshakeComplete:          state.HandshakeComplete,
		NegotiatedProtocol:         state.NegotiatedProtocol,
		NegotiatedProtocolIsMutual: state.NegotiatedProtocolIsMutual,
		ServerName:                 state.ServerName,
	}
}

func tlsStateConn(conn net.Conn) net.Conn {
	if uConn, ok := conn.(*tlsC.UConn); ok {
		return utlsConn{UConn: uConn}
	}
	return conn
}

// secureTransport keeps a host to one connection, all that h2 needs, as without
// a limit parallel requests would each dial their own. A host that answers over
// h1 moves to a transport with more, since h1 carries one request at a time
type secureTransport struct {
	h2, h1  http.RoundTripper
	h1Hosts *sync.Map
}

func (t *secureTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if _, ok := t.h1Hosts.Load(r.URL.Host); ok {
		return t.h1.RoundTrip(r)
	}
	resp, err := t.h2.RoundTrip(r)
	if err == nil && resp.ProtoMajor == 1 {
		t.h1Hosts.Store(r.URL.Host, true)
	}
	return resp, err
}

var errSessionClosed = newError("the session is closed")

// connPool hands the sessions of a storage the connections of XMUX, each a
// client of its own made by newClient
type connPool struct {
	mu   sync.Mutex
	xmux *xmuxManager
}

func newConnPool(config *XmuxConfig, newClient func(connCtx context.Context) *http.Client) *connPool {
	var xmuxConfig XmuxConfig
	if config != nil {
		xmuxConfig = *config
	}
	return &connPool{xmux: newXmuxManager(xmuxConfig, func() xmuxConn {
		ctx, cancel := context.WithCancel(context.Background())
		return &poolConn{next: newClient(ctx).Transport, cancel: cancel}
	})}
}

// poolConn is a connection of XMUX, which closes once XMUX drops it and the
// requests on it end
type poolConn struct {
	next   http.RoundTripper
	cancel context.CancelFunc

	mu       sync.Mutex
	inflight int
	closing  bool
}

func (c *poolConn) IsClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closing
}

func (c *poolConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closing = true
	if c.inflight == 0 {
		c.cancel()
	}
	return nil
}

func (c *poolConn) done() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.inflight--
	if c.closing && c.inflight == 0 {
		c.cancel()
	}
}

// roundTrip sends a request counted in inflight by the caller
func (c *poolConn) roundTrip(r *http.Request) (*http.Response, error) {
	resp, err := c.next.RoundTrip(r)
	if err != nil {
		c.done()
		return nil, err
	}
	resp.Body = &doneBody{ReadCloser: resp.Body, done: onceFunc(c.done)}
	return resp, nil
}

type doneBody struct {
	io.ReadCloser
	done func()
}

func (b *doneBody) Close() error {
	err := b.ReadCloser.Close()
	b.done()
	return err
}

// a connection that has not answered yet is given this long before its
// timeouts retire it, so that a dial or handshake is not cut short again
var stalledGrace = 12 * time.Second

// sessionTransport sends the requests of one session over a connection of
// XMUX, and over another once that one has no requests or time left
type sessionTransport struct {
	pool *connPool

	mu                sync.Mutex
	client            *xmuxClient
	closed            bool
	slowAt, retiredAt time.Time
	movedAt           time.Time
	takenAt           time.Time
	served            bool
}

func (t *sessionTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return nil, errSessionClosed
	}
	client := t.client
	if client == nil || client.conn.IsClosed() || client.leftRequests.Add(-1) < 0 || !client.unreusableAt.IsZero() && time.Now().After(client.unreusableAt) {
		t.pool.mu.Lock()
		t.client = t.pool.xmux.getClient()
		t.pool.mu.Unlock()
		t.client.addRunning()
		t.client.leftRequests.Add(-1)
		if client != nil {
			client.doneRunning()
			t.movedAt = time.Now()
		}
		client = t.client
		t.takenAt, t.served = time.Now(), false
	}
	// counted under mu, or another request of the session that moves on could
	// close the connection before this one is sent
	conn := client.conn.(*poolConn)
	conn.mu.Lock()
	conn.inflight++
	conn.mu.Unlock()
	t.mu.Unlock()
	resp, err := conn.roundTrip(r)
	if err == nil {
		t.mu.Lock()
		if t.client == client {
			t.served = true
		}
		t.mu.Unlock()
	}
	return resp, err
}

func (t *sessionTransport) stalled(began time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if began.Before(t.movedAt) {
		return
	}
	now := time.Now()
	if !t.served && now.Sub(t.takenAt) < stalledGrace {
		return
	}
	slow := now.Sub(t.slowAt) < 3*time.Second
	t.slowAt = now
	if !slow || t.client == nil || now.Sub(t.retiredAt) < 2*time.Second {
		return
	}
	t.retiredAt = now
	t.client.conn.(*poolConn).Close()
}

func (t *sessionTransport) Close() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.closed = true
	if t.client != nil {
		t.client.doneRunning()
		t.client = nil
	}
}
