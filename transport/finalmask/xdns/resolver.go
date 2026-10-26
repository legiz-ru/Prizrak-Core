package xdns

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"

	"github.com/metacubex/mihomo/common/contextutils"
	"github.com/metacubex/mihomo/transport/finalmask"
)

// Resolver is a DNS server the client sends its queries to, over UDP or TCP.
type Resolver interface {
	Addr() *net.UDPAddr
	Read(p []byte) (int, error)
	Send(p []byte)
	Close()
}

// ResolverConfig is one resolver: Type "udp" or "tcp", Addr host:port.
type ResolverConfig struct {
	Type string
	Addr string
}

func NewResolver(ctx context.Context, config ResolverConfig, dialer *finalmask.Dialer) (Resolver, error) {
	switch config.Type {
	case "tcp":
		return NewTCPResolver(ctx, config, dialer)
	case "udp":
		return NewUDPResolver(ctx, config, dialer)
	default:
		return nil, errors.New("unknown type")
	}
}

type TCPResolver struct {
	ctx    context.Context
	addr   string
	dialer *finalmask.Dialer

	conn    net.Conn
	udpAddr atomic.Pointer[net.UDPAddr]

	readCh  chan []byte
	closeCh chan struct{}
	wg      sync.WaitGroup
	mu      sync.Mutex
	// writeMu keeps frames whole without holding mu, so Close can interrupt
	// a write stalled on a peer that stopped reading.
	writeMu sync.Mutex
}

func NewTCPResolver(ctx context.Context, config ResolverConfig, dialer *finalmask.Dialer) (Resolver, error) {
	r := &TCPResolver{
		ctx:     contextutils.WithoutCancel(ctx),
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

func (r *TCPResolver) closed() bool {
	select {
	case <-r.closeCh:
		return true
	default:
		return false
	}
}

func (r *TCPResolver) dial() error {
	if r.closed() {
		return errors.New("closed")
	}
	if r.conn != nil {
		return nil
	}
	conn, err := r.dialer.DialTCP(r.ctx, r.addr)
	if err != nil {
		return err
	}
	r.conn = conn
	if tcpAddr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		r.udpAddr.Store(&net.UDPAddr{IP: tcpAddr.IP, Port: tcpAddr.Port})
	} else if udpAddr, err := net.ResolveUDPAddr("udp", r.addr); err == nil {
		r.udpAddr.Store(udpAddr)
	} else {
		r.udpAddr.Store(&net.UDPAddr{IP: net.IPv4zero})
	}
	r.wg.Add(1)
	go r.recv(conn)
	return nil
}

func (r *TCPResolver) recv(conn net.Conn) {
	defer r.wg.Done()

	var buf [4096]byte
	for {
		_, err := io.ReadFull(conn, buf[:2])
		if err != nil {
			break
		}
		n := binary.BigEndian.Uint16(buf[:2])
		if n == 0 || n > 4096 {
			_, _ = io.CopyN(io.Discard, conn, int64(n))
			continue
		}
		_, err = io.ReadFull(conn, buf[:n])
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

func (r *TCPResolver) Addr() *net.UDPAddr {
	return r.udpAddr.Load()
}

func (r *TCPResolver) Read(p []byte) (n int, err error) {
	packet, ok := <-r.readCh
	if ok {
		n = copy(p, packet)
		pool4K.Put(packet[:cap(packet)])
		return n, nil
	}
	return 0, io.ErrClosedPipe
}

func (r *TCPResolver) Send(p []byte) {
	r.mu.Lock()
	if r.dial() != nil {
		r.mu.Unlock()
		return
	}
	conn := r.conn
	r.mu.Unlock()

	// DNS over TCP prefixes each message with its length (RFC 1035 4.2.2).
	frame := make([]byte, 2+len(p))
	binary.BigEndian.PutUint16(frame, uint16(len(p)))
	copy(frame[2:], p)
	r.writeMu.Lock()
	_, err := conn.Write(frame)
	r.writeMu.Unlock()
	if err != nil {
		// recv sees the closed conn and resets it, so the next Send redials.
		_ = conn.Close()
	}
}

func (r *TCPResolver) Close() {
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
		ctx:     contextutils.WithoutCancel(ctx),
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
