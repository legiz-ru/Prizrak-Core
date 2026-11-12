package xdns

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"

	"github.com/metacubex/mihomo/transport/finalmask"
)

// Resolver is a DNS server the client sends its queries to: over UDP, TCP or
// HTTPS (DoH). Send may wait for the resolver to take the query, Read gives
// the answers in the order they come.
type Resolver interface {
	Addr() *net.UDPAddr
	Read(p []byte) (int, error)
	Send(p []byte)
	Close()
}

// ResolverConfig is one resolver: Type "udp", "tcp" or "https", Addr
// host:port or, for https, the URL.
type ResolverConfig struct {
	Type string
	Addr string
	// Worker is how many queries tcp and https have in flight at once.
	Worker int
	// TLS and QUIC are the tls-config and quic-config of https; nil TLS is
	// the default one.
	TLS  *TLSConfig
	QUIC *QUICConfig
}

func NewResolver(ctx context.Context, config ResolverConfig, dialer *finalmask.Dialer) (Resolver, error) {
	switch config.Type {
	case "tcp":
		return NewTCPResolver(ctx, config, dialer)
	case "udp":
		return NewUDPResolver(ctx, config, dialer)
	case "https":
		return NewDOHResolver(ctx, config, dialer)
	default:
		return nil, errors.New("unknown type")
	}
}

type UDPResolver struct {
	ctx    context.Context
	addr   string
	dialer *finalmask.Dialer

	conn    net.PacketConn
	udpAddr atomic.Pointer[net.UDPAddr]

	readCh  chan []byte
	closeCh chan struct{}
	wg      sync.WaitGroup
	mu      sync.Mutex
}

func NewUDPResolver(ctx context.Context, config ResolverConfig, dialer *finalmask.Dialer) (Resolver, error) {
	r := &UDPResolver{
		ctx:     dialContext(ctx),
		addr:    config.Addr,
		dialer:  dialer,
		readCh:  make(chan []byte),
		closeCh: make(chan struct{}),
	}
	if err := r.dial(); err != nil {
		r.Close()
		return nil, err
	}
	return r, nil
}

func (r *UDPResolver) closed() bool {
	select {
	case <-r.closeCh:
		return true
	default:
		return false
	}
}

func (r *UDPResolver) dial() error {
	if r.closed() {
		return errors.New("closed")
	}
	if r.conn != nil {
		return nil
	}
	conn, addr, err := r.dialer.DialUDP(r.ctx, r.addr)
	if err != nil {
		return err
	}
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		_ = conn.Close()
		return errors.New("xdns: resolver address is not UDP")
	}
	r.conn = conn
	r.udpAddr.Store(udpAddr)
	r.wg.Add(1)
	go r.recv(conn)
	return nil
}

func (r *UDPResolver) recv(conn net.PacketConn) {
	defer r.wg.Done()

	var buf [4096]byte
	for {
		n, _, err := conn.ReadFrom(buf[:])
		if err != nil {
			break
		}
		p := pool4K.Get().([]byte)
		copy(p, buf[:n])
		select {
		case <-r.closeCh:
			pool4K.Put(p[:cap(p)])
		case r.readCh <- p[:n]:
		}
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	_ = conn.Close()
	if r.conn == conn {
		r.conn = nil
	}
}

func (r *UDPResolver) Addr() *net.UDPAddr {
	return r.udpAddr.Load()
}

func (r *UDPResolver) Read(p []byte) (n int, err error) {
	packet, ok := <-r.readCh
	if ok {
		n = copy(p, packet)
		pool4K.Put(packet[:cap(packet)])
		return n, nil
	}
	return 0, io.ErrClosedPipe
}

func (r *UDPResolver) Send(p []byte) {
	r.mu.Lock()
	if err := r.dial(); err != nil {
		r.mu.Unlock()
		return
	}
	conn := r.conn
	r.mu.Unlock()
	// Write outside mu: a conn behind a dialer-proxy can block until Close
	// closes it, and Close needs mu to reach it.
	_, _ = conn.WriteTo(p, r.udpAddr.Load())
}

func (r *UDPResolver) Close() {
	r.mu.Lock()
	if r.closed() {
		r.mu.Unlock()
		return
	}
	close(r.closeCh)
	conn := r.conn
	r.mu.Unlock()
	if conn != nil {
		_ = conn.Close()
	}
	r.wg.Wait()
	close(r.readCh)
}
