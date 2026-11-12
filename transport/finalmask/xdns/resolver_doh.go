package xdns

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/contextutils"
	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/component/ech"
	tlsC "github.com/metacubex/mihomo/component/tls"
	"github.com/metacubex/mihomo/transport/finalmask"
	tuicCommon "github.com/metacubex/mihomo/transport/tuic/common"

	"github.com/metacubex/http"
	"github.com/metacubex/quic-go"
	"github.com/metacubex/quic-go/http3"
	hyCongestion "github.com/metacubex/sing-quic/hysteria2/congestion"
	"github.com/metacubex/sing/common/logger"
	"github.com/metacubex/tls"
)

// dohIdleTimeout closes a DoH connection nothing used for this long.
const dohIdleTimeout = 90 * time.Second

// DOHResolver is DNS over HTTPS as in Xray-core since 10879a4a: up to worker
// POSTs of application/dns-message in flight, with no User-Agent, over
// HTTP/2 or HTTP/1.1 as ALPN picks (a Chrome Client Hello by default) or over
// HTTP/3 when alpn is exactly h3. A 429 with Retry-After drops the queries
// until it passes.
type DOHResolver struct {
	workQueue

	// ctx is that of the requests, cancelled by Close. It carries no value
	// of the caller's: one dialing through XHTTP has the hooks of its own
	// request in it, which the queries must not call.
	ctx    context.Context
	cancel context.CancelFunc
	// dialCtx keeps the caller's values for the mask's dials.
	dialCtx context.Context
	client  *http.Client
	close   func()
	url     string

	mu       sync.Mutex
	cooldown time.Time
	// conns are the TCP connections under the TLS of HTTP/1.1 and HTTP/2,
	// which Close closes: net/http would keep one whose requests Close
	// cancelled until it idles out.
	conns map[*dohConn]struct{}
}

func NewDOHResolver(ctx context.Context, config ResolverConfig, dialer *finalmask.Dialer) (Resolver, error) {
	if config.Worker < 1 {
		return nil, fmt.Errorf("xdns: https resolver %s needs at least one worker", config.Addr)
	}
	u, err := url.Parse(config.Addr)
	if err != nil {
		return nil, err
	}
	tlsConfig := config.TLS
	if tlsConfig == nil {
		tlsConfig, err = (&TLSOption{}).Build()
		if err != nil {
			return nil, err
		}
	}
	serverName := tlsConfig.ServerName
	if serverName == "" {
		serverName = u.Hostname()
	}
	reqCtx, cancel := context.WithCancel(context.Background())
	r := &DOHResolver{
		ctx:     reqCtx,
		cancel:  cancel,
		dialCtx: dialContext(ctx),
		url:     config.Addr,
		conns:   map[*dohConn]struct{}{},
	}
	r.init()
	var transport http.RoundTripper
	if tlsConfig.H3() {
		h3, err := r.h3Transport(tlsConfig, config.QUIC, serverName, dialer)
		if err != nil {
			cancel()
			return nil, err
		}
		transport = h3
		r.close = func() { _ = h3.Close() }
	} else {
		tcp := r.tcpTransport(tlsConfig, serverName, dialer, config.Worker)
		transport = tcp
		r.close = tcp.CloseIdleConnections
	}
	// Redirects are not followed, as in ferrum: the request to another
	// place would go out of the mask's dials, by plain HTTP if so told.
	r.client = &http.Client{
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	for i := 0; i < config.Worker; i++ {
		r.wg.Add(1)
		go r.worker()
	}
	return r, nil
}

// stdTLSConfig is the Go TLS of the resolver, which the uTLS one is made
// from: the roots of the core, and the checks of the pins and names.
func stdTLSConfig(c *TLSConfig, serverName string, nextProtos []string) (*tls.Config, error) {
	config, err := ca.GetTLSConfig(ca.Option{TLSConfig: &tls.Config{ServerName: serverName, NextProtos: nextProtos}})
	if err != nil {
		return nil, err
	}
	if len(c.Pins) > 0 || len(c.VerifyNames) > 0 {
		roots, now := config.RootCAs, config.Time
		config.InsecureSkipVerify = true
		config.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			at := time.Now()
			if now != nil {
				at = now()
			}
			return c.verifyPeer(rawCerts, roots, serverName, at)
		}
	}
	return config, nil
}

func (c *TLSConfig) echConfig() *ech.Config {
	if len(c.ECH) == 0 {
		return nil
	}
	list := c.ECH
	return &ech.Config{GetEncryptedClientHelloConfigList: func(context.Context, string) ([]byte, error) {
		return list, nil
	}}
}

// tcpTransport is Xray's http.Transport with ForceAttemptHTTP2 and a dial
// that does the resolver's TLS, HTTP/2 or HTTP/1.1 by the ALPN of the
// connection.
func (r *DOHResolver) tcpTransport(c *TLSConfig, serverName string, dialer *finalmask.Dialer, worker int) *dohTransport {
	nextProtos := c.NextProtos
	if len(nextProtos) == 0 {
		nextProtos = []string{"h2", "http/1.1"}
	}
	t := &dohTransport{wake: make(chan struct{})}
	if c.Fingerprint == "" && !containsString(nextProtos, "h2") {
		// Go's TLS offers only what alpn says (uTLS offers its hello's
		// own): such a resolver speaks HTTP/1.1 from the start.
		t.proto = 1
	}
	dialTLS := func(_ context.Context, network, addr string) (net.Conn, error) {
		// net/http dials apart from the request; Close still ends the dial.
		ctx, cancel := context.WithTimeout(r.dialCtx, dialTimeout)
		defer cancel()
		stop := contextutils.AfterFunc(r.ctx, cancel)
		defer stop()
		raw, err := dialer.DialTCP(ctx, addr)
		if err != nil {
			return nil, err
		}
		r.setAddr(raw.RemoteAddr(), addr)
		conn := &dohConn{Conn: raw, r: r}
		if !r.track(conn) {
			_ = raw.Close()
			return nil, errResolverClosed
		}
		tlsConn, err := dialTLS(ctx, conn, c, serverName, nextProtos)
		if err != nil {
			_ = conn.Close()
			return nil, err
		}
		state := tlsConn.(interface{ ConnectionState() tls.ConnectionState }).ConnectionState()
		t.learn(state.NegotiatedProtocol)
		return tlsConn, nil
	}
	transport := func(connsPerHost int) *http.Transport {
		return &http.Transport{
			// Plain http:// is never dialed past the mask.
			DialContext: func(context.Context, string, string) (net.Conn, error) {
				return nil, errors.New("xdns: a DoH resolver speaks https only")
			},
			DialTLSContext:      dialTLS,
			ForceAttemptHTTP2:   true,
			IdleConnTimeout:     dohIdleTimeout,
			MaxConnsPerHost:     connsPerHost,
			MaxIdleConnsPerHost: worker,
		}
	}
	t.h2, t.h1 = transport(1), transport(0)
	return t
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// dohTransport keeps an HTTP/2 resolver to one connection and lets an
// HTTP/1.1 one have a connection per worker. net/http dials for every
// request that finds no connection ready, and the workers start together:
// over HTTP/2 that would be a TLS handshake per worker, all but one closed
// right away. So until a connection has told the protocol by its ALPN, one
// request dials and the others wait; then HTTP/2 goes on a transport of one
// connection and HTTP/1.1 on one without a limit.
type dohTransport struct {
	h2, h1 *http.Transport

	mu      sync.Mutex
	proto   int  // 0 while not known, 1 or 2
	leading bool // a request is finding the protocol out
	wake    chan struct{}
}

// learn takes the protocol of a connection: HTTP/1.1 from any connection
// for good, HTTP/2 while nothing said otherwise.
func (t *dohTransport) learn(alpn string) {
	proto := 1
	if alpn == "h2" {
		proto = 2
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.proto == proto || t.proto == 1 {
		return
	}
	known := t.proto == 0
	t.proto = proto
	if known {
		close(t.wake)
		t.wake = make(chan struct{})
	}
}

func (t *dohTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	for {
		t.mu.Lock()
		switch {
		case t.proto == 1:
			t.mu.Unlock()
			return t.h1.RoundTrip(req)
		case t.proto == 2:
			t.mu.Unlock()
			return t.h2.RoundTrip(req)
		case !t.leading:
			t.leading = true
			t.mu.Unlock()
			resp, err := t.h2.RoundTrip(req)
			t.mu.Lock()
			t.leading = false
			if t.proto == 0 {
				// The dial failed: the next request tries.
				close(t.wake)
				t.wake = make(chan struct{})
			}
			t.mu.Unlock()
			return resp, err
		}
		wake := t.wake
		t.mu.Unlock()
		select {
		case <-wake:
		case <-req.Context().Done():
			return nil, req.Context().Err()
		}
	}
}

func (t *dohTransport) CloseIdleConnections() {
	t.h2.CloseIdleConnections()
	t.h1.CloseIdleConnections()
}

// dohConn is a TCP connection of the resolver, which Close closes.
type dohConn struct {
	net.Conn
	r    *DOHResolver
	once sync.Once
}

func (c *dohConn) Close() error {
	c.once.Do(func() { c.r.untrack(c) })
	return c.Conn.Close()
}

func (r *DOHResolver) track(c *dohConn) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed() {
		return false
	}
	r.conns[c] = struct{}{}
	return true
}

func (r *DOHResolver) untrack(c *dohConn) {
	r.mu.Lock()
	delete(r.conns, c)
	r.mu.Unlock()
}

func dialTLS(ctx context.Context, conn net.Conn, c *TLSConfig, serverName string, nextProtos []string) (net.Conn, error) {
	config, err := stdTLSConfig(c, serverName, nextProtos)
	if err != nil {
		return nil, err
	}
	echConfig := c.echConfig()
	if c.Fingerprint != "" {
		fingerprint, ok := tlsC.GetFingerprint(c.Fingerprint)
		if !ok {
			return nil, fmt.Errorf("xdns: unknown fingerprint %q", c.Fingerprint)
		}
		uConfig := tlsC.UConfig(config)
		if err := echConfig.ClientHandleUTLS(ctx, uConfig); err != nil {
			return nil, err
		}
		uConn := tlsC.UClient(conn, uConfig, fingerprint)
		if err := uConn.HandshakeContext(ctx); err != nil {
			return nil, err
		}
		return utlsStateConn{UConn: uConn}, nil
	}
	if err := echConfig.ClientHandle(ctx, config); err != nil {
		return nil, err
	}
	tlsConn := tls.Client(conn, config)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	return tlsConn, nil
}

// utlsStateConn gives http.Transport the ConnectionState of a uTLS
// connection, whose own has a type of uTLS, for the ALPN it picks HTTP/2 or
// HTTP/1.1 by (Xray wraps its UConn the same way).
type utlsStateConn struct {
	*tlsC.UConn
}

func (c utlsStateConn) ConnectionState() tls.ConnectionState {
	state := c.UConn.ConnectionState()
	return tls.ConnectionState{
		Version:                    state.Version,
		HandshakeComplete:          state.HandshakeComplete,
		DidResume:                  state.DidResume,
		CipherSuite:                state.CipherSuite,
		NegotiatedProtocol:         state.NegotiatedProtocol,
		NegotiatedProtocolIsMutual: state.NegotiatedProtocolIsMutual,
		ServerName:                 state.ServerName,
		PeerCertificates:           state.PeerCertificates,
		VerifiedChains:             state.VerifiedChains,
		ECHAccepted:                state.ECHAccepted,
	}
}

// h3Transport is Xray's http3.Transport over the mask's UDP dial, with the
// quic-config's windows, timeouts and congestion control.
func (r *DOHResolver) h3Transport(c *TLSConfig, q *QUICConfig, serverName string, dialer *finalmask.Dialer) (*http3.Transport, error) {
	if q == nil {
		// Xray's defaults, path MTU discovery off where Xray turns it off.
		var err error
		if q, err = (&QUICOption{}).Build(); err != nil {
			return nil, err
		}
	}
	config, err := stdTLSConfig(c, serverName, []string{"h3"})
	if err != nil {
		return nil, err
	}
	if err := c.echConfig().ClientHandle(r.ctx, config); err != nil {
		return nil, err
	}
	quicConfig := &quic.Config{
		InitialStreamReceiveWindow:     q.InitialStreamReceiveWindow,
		MaxStreamReceiveWindow:         q.MaxStreamReceiveWindow,
		InitialConnectionReceiveWindow: q.InitialConnectionReceiveWindow,
		MaxConnectionReceiveWindow:     q.MaxConnectionReceiveWindow,
		MaxIdleTimeout:                 q.MaxIdleTimeout,
		KeepAlivePeriod:                q.KeepAlivePeriod,
		DisablePathMTUDiscovery:        q.DisablePathMTUDiscovery,
	}
	dial := func(_ context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
		ctx, cancel := context.WithTimeout(r.dialCtx, dialTimeout)
		defer cancel()
		stop := contextutils.AfterFunc(r.ctx, cancel)
		defer stop()
		pc, raddr, err := dialer.DialUDP(ctx, addr)
		if err != nil {
			return nil, err
		}
		r.setAddr(raddr, addr)
		transport := quic.Transport{Conn: pc}
		transport.SetCreatedConn(true) // the connection closes the socket
		transport.SetSingleUse(true)   // and the transport
		conn, err := transport.Dial(ctx, raddr, tlsCfg, cfg)
		if err != nil {
			_ = transport.Close()
			_ = pc.Close()
			return nil, err
		}
		switch q.Congestion {
		case "bbr":
			tuicCommon.SetCongestionController(conn, "bbr", 0, q.BBRProfile)
		case "force-brutal":
			conn.SetCongestionControl(hyCongestion.NewBrutalSender(q.BrutalUp, false, logger.NOP()))
		}
		return conn, nil
	}
	return &http3.Transport{
		TLSClientConfig: config,
		QUICConfig:      quicConfig,
		Dial:            dial,
	}, nil
}

// cooling reports whether a 429 asked to wait.
func (r *DOHResolver) cooling() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return time.Now().Before(r.cooldown)
}

func (r *DOHResolver) coolUntil(t time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if t.After(r.cooldown) {
		r.cooldown = t
	}
}

func (r *DOHResolver) worker() {
	defer r.wg.Done()
	for {
		p, ok := r.next()
		if !ok {
			return
		}
		// A 429's Retry-After, or connections that keep failing, pause the
		// resolver: the query is dropped.
		if r.cooling() || r.backoff.cooling() {
			continue
		}
		if err := r.do(p); err != nil {
			r.warn("https resolver %s: %v", r.url, err)
		}
	}
}

// do POSTs p and passes a 200 answer on. An answer that fills the 4 KiB
// buffer is dropped, as Xray drops it.
func (r *DOHResolver) do(p []byte) error {
	req, err := http.NewRequestWithContext(r.ctx, http.MethodPost, r.url, bytes.NewReader(p))
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/dns-message")
	req.Header.Set("Content-Type", "application/dns-message")
	// An empty User-Agent sends none.
	req.Header.Set("User-Agent", "")
	resp, err := r.client.Do(req)
	if err != nil {
		// No answer at all (the dial, the TLS or the connection failed):
		// pause, so a resolver that is down is not dialed by every query.
		if r.ctx.Err() == nil {
			r.backoff.fail()
		}
		return err
	}
	r.backoff.ok()
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		b := pool4K.Get().([]byte)
		n, err := io.ReadFull(resp.Body, b[:maxMessage])
		switch {
		case err == nil:
			pool4K.Put(b[:cap(b)])
			return errors.New("answer longer than 4096 bytes dropped")
		case errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF):
			if n == 0 {
				pool4K.Put(b[:cap(b)])
				return errors.New("empty answer")
			}
			r.deliver(b[:n])
			return nil
		default:
			pool4K.Put(b[:cap(b)])
			return err
		}
	case http.StatusTooManyRequests:
		if value := resp.Header.Get("Retry-After"); value != "" {
			if t, err := http.ParseTime(value); err == nil {
				r.coolUntil(t)
			} else if s, err := strconv.ParseUint(value, 10, 32); err == nil {
				r.coolUntil(time.Now().Add(time.Duration(s) * time.Second))
			}
		}
	}
	return fmt.Errorf("status %d", resp.StatusCode)
}

// Close ends the requests in flight and the workers, then the connections.
func (r *DOHResolver) Close() {
	r.mu.Lock()
	if r.closed() {
		r.mu.Unlock()
		return
	}
	close(r.closeCh)
	r.mu.Unlock()
	r.cancel()
	r.wg.Wait()
	r.close()
	r.mu.Lock()
	conns := make([]*dohConn, 0, len(r.conns))
	for c := range r.conns {
		conns = append(conns, c)
	}
	r.mu.Unlock()
	for _, c := range conns {
		_ = c.Close()
	}
	close(r.readCh)
}
