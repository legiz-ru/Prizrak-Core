// Package xicmp is the "xicmp" finalmask of Xray-core: datagrams travel as
// ICMP echo requests to the server and come back as echo replies. The client
// needs raw ICMP sockets, or the unprivileged datagram ICMP sockets of Linux
// (ping_group_range) and macOS with dgram: true.
package xicmp

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	goerrors "errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/transport/finalmask"
	"github.com/metacubex/randv2"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// Config is the mask's settings, as written in the config.
type Config struct {
	// DGRAM uses unprivileged datagram ICMP sockets instead of raw ones.
	DGRAM bool `proxy:"dgram,omitempty"`
	// IPs are the server addresses to send to, in turn; the destination's
	// own address when empty, which then has to be an IP.
	IPs []string `proxy:"ips,omitempty"`
}

func New(c Config) (*Config, error) {
	for _, ip := range c.IPs {
		if _, err := netip.ParseAddr(ip); err != nil {
			return nil, fmt.Errorf("xicmp: invalid ip %q", ip)
		}
	}
	return &c, nil
}

func (c *Config) HandleDial() {}

func (c *Config) WrapPacketConnClient(_ context.Context, _ net.PacketConn, dest *finalmask.Destination, _ *finalmask.Dialer) (net.PacketConn, error) {
	if _, ok := dest.IP(); !ok && len(c.IPs) == 0 {
		return nil, goerrors.New("xicmp: the server is a domain, set ips")
	}
	return NewConnClient(c, dest)
}

func (c *Config) WrapPacketConnServer(net.PacketConn) (net.PacketConn, error) {
	return nil, goerrors.New("xicmp: client only")
}

var pool = sync.Pool{
	New: func() any {
		return make([]byte, finalmask.UDPSize)
	},
}

type packet struct {
	p    []byte
	addr net.Addr
	err  error
}

// icmpSocket is what the client needs from an ICMP socket; tests supply
// their own.
type icmpSocket interface {
	ReadFrom(b []byte) (int, net.Addr, error)
	WriteTo(b []byte, dst net.Addr) (int, error)
	Close() error
	SetDeadline(t time.Time) error
	SetReadDeadline(t time.Time) error
	SetWriteDeadline(t time.Time) error
}

var listenICMP = func(dgram bool) (icmpSocket, icmpSocket, error) {
	var icmp4, icmp6 *icmp.PacketConn
	var err4, err6 error
	if dgram {
		icmp4, err4 = icmp.ListenPacket("udp4", "0.0.0.0")
		icmp6, err6 = icmp.ListenPacket("udp6", "::")
	} else {
		icmp4, err4 = icmp.ListenPacket("ip4:icmp", "0.0.0.0")
		icmp6, err6 = icmp.ListenPacket("ip6:ipv6-icmp", "::")
	}
	// One family is enough when the other is not available on this host.
	if err4 != nil && err6 != nil {
		return nil, nil, goerrors.Join(err4, err6)
	}
	var s4, s6 icmpSocket
	if icmp4 != nil {
		s4 = icmp4
	}
	if icmp6 != nil {
		s6 = icmp6
	}
	return s4, s6, nil
}

type clientConn struct {
	icmp4    icmpSocket
	icmp6    icmpSocket
	udp      bool
	ips      []netip.Addr
	ip       net.IP
	clientID [8]byte
	id       int
	seq      int
	readCh   chan packet
	closeCh  chan struct{}
	wg       sync.WaitGroup
	mu       sync.Mutex
}

func NewConnClient(c *Config, dest *finalmask.Destination) (net.PacketConn, error) {
	icmp4, icmp6, err := listenICMP(c.DGRAM)
	if err != nil {
		return nil, fmt.Errorf("xicmp: %w", err)
	}

	ips := make([]netip.Addr, 0, len(c.IPs))
	for _, ip := range c.IPs {
		ips = append(ips, netip.MustParseAddr(ip))
	}

	var ip net.IP
	if len(ips) > 0 {
		ip = ips[randv2.IntN(len(ips))].AsSlice()
	} else {
		addr, _ := dest.IP()
		ip = addr.AsSlice()
	}

	var clientID [8]byte
	if _, err := rand.Read(clientID[:]); err != nil {
		panic(err)
	}

	conn := &clientConn{
		icmp4:    icmp4,
		icmp6:    icmp6,
		udp:      c.DGRAM,
		ips:      ips,
		ip:       ip,
		clientID: clientID,
		id:       randv2.IntN(65536),
		seq:      1,
		readCh:   make(chan packet),
		closeCh:  make(chan struct{}),
	}

	if icmp4 != nil {
		conn.wg.Add(1)
		go conn.recv(icmp4, 1, ipv4.ICMPTypeEchoReply)
	}
	if icmp6 != nil {
		conn.wg.Add(1)
		go conn.recv(icmp6, 58, ipv6.ICMPTypeEchoReply)
	}

	return conn, nil
}

func (c *clientConn) closed() bool {
	select {
	case <-c.closeCh:
		return true
	default:
		return false
	}
}

func (c *clientConn) recv(sock icmpSocket, proto int, reply icmp.Type) {
	defer c.wg.Done()

	var b [finalmask.UDPSize]byte
	for {
		n, addr, err := sock.ReadFrom(b[:])
		if err != nil {
			if c.closed() {
				return
			}
			var netErr net.Error
			if goerrors.As(err, &netErr) && netErr.Timeout() {
				select {
				case c.readCh <- packet{err: err}:
				case <-c.closeCh:
					return
				}
				continue
			}
			log.Warnln("[finalmask] xicmp: recv failed: %v", err)
			return
		}

		msg, err := icmp.ParseMessage(proto, b[:n])
		if err != nil {
			continue
		}

		if msg.Type != reply {
			continue
		}

		echo, ok := msg.Body.(*icmp.Echo)
		if !ok {
			continue
		}

		if !c.udp && echo.ID != c.id {
			continue
		}

		// Our own request echoed back by a middlebox.
		if len(echo.Data) > 8 && bytes.Equal(echo.Data[:8], c.clientID[:]) {
			continue
		}

		p := pool.Get().([]byte)[:len(echo.Data)]
		copy(p, echo.Data)

		if ipAddr, ok := addr.(*net.IPAddr); ok {
			addr = &net.UDPAddr{IP: ipAddr.IP}
		}

		select {
		case c.readCh <- packet{p: p, addr: addr}:
		case <-c.closeCh:
			pool.Put(p[:cap(p)])
			return
		}
	}
}

func (c *clientConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	packet, ok := <-c.readCh
	if ok {
		if packet.p != nil {
			n = copy(p, packet.p)
			pool.Put(packet.p[:cap(packet.p)])
		}
		return n, packet.addr, packet.err
	}
	return 0, nil, io.EOF
}

// WriteTo sends p as an echo request to one of the server's addresses; the
// client ID in front of the data lets the server tell clients apart.
func (c *clientConn) WriteTo(p []byte, _ net.Addr) (n int, err error) {
	if len(p)+16 > finalmask.UDPSize {
		log.Debugln("[finalmask] xicmp: drop packet with size %d", len(p))
		return 0, nil
	}

	c.mu.Lock()
	seq := c.seq
	c.seq += 1
	c.seq %= 65536
	c.mu.Unlock()

	ip := c.ip
	if len(c.ips) > 0 {
		ip = c.ips[randv2.IntN(len(c.ips))].AsSlice()
	}

	var addr net.Addr
	if c.udp {
		addr = &net.UDPAddr{IP: ip}
	} else {
		addr = &net.IPAddr{IP: ip}
	}

	b := pool.Get().([]byte)[:finalmask.UDPSize]
	defer pool.Put(b[:cap(b)])

	copy(b[8:], c.clientID[:])
	copy(b[16:], p)

	if ip.To4() != nil {
		if c.icmp4 == nil {
			return 0, goerrors.New("xicmp: no IPv4 socket")
		}
		b = marshal(b, ipv4.ICMPTypeEcho, c.id, seq, 8+len(p))
		_, err = c.icmp4.WriteTo(b, addr)
	} else {
		if c.icmp6 == nil {
			return 0, goerrors.New("xicmp: no IPv6 socket")
		}
		b = marshal(b, ipv6.ICMPTypeEchoRequest, c.id, seq, 8+len(p))
		_, err = c.icmp6.WriteTo(b, addr)
	}

	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *clientConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed() {
		return nil
	}
	close(c.closeCh)
	if c.icmp4 != nil {
		_ = c.icmp4.Close()
	}
	if c.icmp6 != nil {
		_ = c.icmp6.Close()
	}
	c.wg.Wait()
	close(c.readCh)
	return nil
}

func (c *clientConn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4zero}
}

func (c *clientConn) each(f func(icmpSocket) error) error {
	if c.icmp4 != nil {
		_ = f(c.icmp4)
	}
	if c.icmp6 != nil {
		_ = f(c.icmp6)
	}
	return nil
}

func (c *clientConn) SetDeadline(t time.Time) error {
	return c.each(func(s icmpSocket) error { return s.SetDeadline(t) })
}

func (c *clientConn) SetReadDeadline(t time.Time) error {
	return c.each(func(s icmpSocket) error { return s.SetReadDeadline(t) })
}

func (c *clientConn) SetWriteDeadline(t time.Time) error {
	return c.each(func(s icmpSocket) error { return s.SetWriteDeadline(t) })
}

// marshal writes an echo header in front of the dataLen bytes at b[8:]. The
// IPv4 checksum covers the message; the kernel computes the IPv6 one.
func marshal(b []byte, typ icmp.Type, id, seq int, dataLen int) []byte {
	is4 := false
	switch typ := typ.(type) {
	case ipv4.ICMPType:
		is4 = true
		b[0] = byte(typ)
	case ipv6.ICMPType:
		b[0] = byte(typ)
	default:
		panic(fmt.Sprintf("%T %v", typ, typ))
	}
	b[1], b[2], b[3] = 0, 0, 0
	binary.BigEndian.PutUint16(b[4:], uint16(id))
	binary.BigEndian.PutUint16(b[6:], uint16(seq))
	if is4 {
		s := checksum(b[:8+dataLen])
		b[2] ^= byte(s)
		b[3] ^= byte(s >> 8)
	}
	return b[:8+dataLen]
}

// checksum is the RFC 1071 one's complement sum, as golang.org/x/net/icmp
// computes it.
func checksum(b []byte) uint16 {
	csumcv := len(b) - 1 // checksum coverage
	s := uint32(0)
	for i := 0; i < csumcv; i += 2 {
		s += uint32(b[i+1])<<8 | uint32(b[i])
	}
	if csumcv&1 == 0 {
		s += uint32(b[csumcv])
	}
	s = s>>16 + s&0xffff
	s = s + s>>16
	return ^uint16(s)
}
