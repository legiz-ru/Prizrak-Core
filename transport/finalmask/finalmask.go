// Package finalmask ports the finalmask layer of Xray-core (the Jolymmiles
// fork): a chain of masks applied under the transport, between the socket
// and TLS, that reshape the bytes on the wire. TCP masks wrap a stream, UDP
// masks wrap a packet connection.
//
// A chain is written as in Xray: the first mask of the list is the outermost
// (nearest to TLS and the proxy protocol), the last one is the innermost
// (nearest to the socket), so the last entry is what the network sees.
package finalmask

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
)

// UDPSize is the largest datagram a UDP mask carries.
const UDPSize = 4096

// Dialer opens the base sockets for masks that need their own: udphop opens a
// new socket on every hop, xdns reaches its resolvers through it. Addresses
// are host:port, a host may be a domain.
type Dialer struct {
	DialTCP func(ctx context.Context, addr string) (net.Conn, error)
	DialUDP func(ctx context.Context, addr string) (net.PacketConn, net.Addr, error)
}

// Destination is where the chain dials to. A UDP mask that picks its own
// remote (udphop) changes it before the base socket is opened.
type Destination struct {
	Host string
	Port uint16
}

func (d Destination) Addr() string {
	return net.JoinHostPort(d.Host, strconv.Itoa(int(d.Port)))
}

// IP returns the destination's address when it is an IP literal.
func (d Destination) IP() (netip.Addr, bool) {
	ip, err := netip.ParseAddr(d.Host)
	return ip, err == nil
}

// ParseDestination splits a host:port address.
func ParseDestination(addr string) (Destination, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return Destination{}, err
	}
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return Destination{}, fmt.Errorf("invalid port in %q", addr)
	}
	return Destination{Host: host, Port: uint16(p)}, nil
}

// TCPMask reshapes a TCP stream.
type TCPMask interface {
	WrapConnClient(ctx context.Context, conn net.Conn, dest *Destination, dialer *Dialer) (net.Conn, error)
	WrapConnServer(conn net.Conn) (net.Conn, error)
}

// UDPMask reshapes a packet connection. A mask that opens the network itself
// (udphop, xdns, xicmp) also implements DialHandler; it then gets a nil conn
// and must be the innermost mask of the chain.
type UDPMask interface {
	WrapPacketConnClient(ctx context.Context, conn net.PacketConn, dest *Destination, dialer *Dialer) (net.PacketConn, error)
	WrapPacketConnServer(conn net.PacketConn) (net.PacketConn, error)
}

// DialHandler marks a UDP mask that opens the network itself instead of
// wrapping a socket the chain opened.
type DialHandler interface {
	HandleDial()
}

// FinalMask is a chain of TCP masks and a chain of UDP masks.
type FinalMask struct {
	// tcp and udp hold the masks innermost first, so wrapping walks them in
	// order; the config lists them outermost first.
	tcp []TCPMask
	udp []UDPMask
}

// New takes the chains as the config lists them, outermost first.
func New(tcp []TCPMask, udp []UDPMask) (*FinalMask, error) {
	fm := &FinalMask{}
	for i := len(tcp) - 1; i >= 0; i-- {
		fm.tcp = append(fm.tcp, tcp[i])
	}
	for i := len(udp) - 1; i >= 0; i-- {
		fm.udp = append(fm.udp, udp[i])
	}
	for i, mask := range fm.udp {
		if _, ok := mask.(DialHandler); ok && i > 0 {
			return nil, fmt.Errorf("finalmask: UDP mask %T opens the network itself, so it must be the last entry of the list", mask)
		}
	}
	return fm, nil
}

func (fm *FinalMask) HasTCP() bool { return fm != nil && len(fm.tcp) > 0 }

func (fm *FinalMask) HasUDP() bool { return fm != nil && len(fm.udp) > 0 }

// WrapConnClient applies the TCP chain to a dialed connection. The chain
// takes over conn: on an error it is closed.
func (fm *FinalMask) WrapConnClient(ctx context.Context, conn net.Conn, dest *Destination, dialer *Dialer) (net.Conn, error) {
	if !fm.HasTCP() {
		return conn, nil
	}
	if dest == nil {
		dest = &Destination{}
	}
	for _, mask := range fm.tcp {
		wrapped, err := mask.WrapConnClient(ctx, conn, dest, dialer)
		if err != nil {
			_ = conn.Close()
			return nil, err
		}
		conn = wrapped
	}
	return conn, nil
}

// DialTCP dials dest through dialer and applies the TCP chain.
func (fm *FinalMask) DialTCP(ctx context.Context, dest Destination, dialer *Dialer) (net.Conn, error) {
	conn, err := dialer.DialTCP(ctx, dest.Addr())
	if err != nil {
		return nil, err
	}
	return fm.WrapConnClient(ctx, conn, &dest, dialer)
}

// WrapConnServer applies the TCP chain to an accepted connection.
func (fm *FinalMask) WrapConnServer(conn net.Conn) (net.Conn, error) {
	for _, mask := range fm.tcp {
		wrapped, err := mask.WrapConnServer(conn)
		if err != nil {
			_ = conn.Close()
			return nil, err
		}
		conn = wrapped
	}
	return conn, nil
}

// DialUDP opens a packet connection to dest through the UDP chain and returns
// it with the address to send to. Without a chain it is the base socket.
func (fm *FinalMask) DialUDP(ctx context.Context, dest Destination, dialer *Dialer) (net.PacketConn, net.Addr, error) {
	if !fm.HasUDP() {
		return dialer.DialUDP(ctx, dest.Addr())
	}
	var conn net.PacketConn
	var addr net.Addr
	if _, ok := fm.udp[0].(DialHandler); !ok {
		var err error
		conn, addr, err = dialer.DialUDP(ctx, dest.Addr())
		if err != nil {
			return nil, nil, err
		}
	}
	for _, mask := range fm.udp {
		wrapped, err := mask.WrapPacketConnClient(ctx, conn, &dest, dialer)
		if err != nil {
			if conn != nil {
				_ = conn.Close()
			}
			return nil, nil, err
		}
		conn = wrapped
	}
	if addr == nil {
		// A mask that opened the network itself routes by itself; the
		// address only has to be a UDP one for the layers above.
		addr = &net.UDPAddr{IP: net.IPv4zero}
	}
	return conn, addr, nil
}

// WrapPacketConnServer applies the UDP chain to a listening socket.
func (fm *FinalMask) WrapPacketConnServer(conn net.PacketConn) (net.PacketConn, error) {
	for _, mask := range fm.udp {
		if _, ok := mask.(DialHandler); ok && conn == nil {
			return nil, errors.New("finalmask: this UDP mask has no server side")
		}
		wrapped, err := mask.WrapPacketConnServer(conn)
		if err != nil {
			if conn != nil {
				_ = conn.Close()
			}
			return nil, err
		}
		conn = wrapped
	}
	return conn, nil
}

// MaskConn is implemented by TCP mask connections. Splice reports whether
// the relay may bypass the wrapper once its work is done (a header that was
// exchanged, a ClientHello that was split), like Xray's TcpMaskConn.
type MaskConn interface {
	MaskConn()
	RawConn() net.Conn
	Splice() bool
}

// Unwrap returns the innermost connection that still has to see the data.
func Unwrap(conn net.Conn) net.Conn {
	for {
		v, ok := conn.(MaskConn)
		if !ok || !v.Splice() {
			return conn
		}
		conn = v.RawConn()
	}
}

// Listener applies the TCP chain to every accepted connection, as Xray's
// inbound does. A connection the chain refuses is closed and the next one
// is accepted, so a bad peer does not stop the listener.
type Listener struct {
	net.Listener
	fm *FinalMask
}

func NewListener(l net.Listener, fm *FinalMask) net.Listener {
	if !fm.HasTCP() {
		return l
	}
	return &Listener{Listener: l, fm: fm}
}

func (l *Listener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		wrapped, err := l.fm.WrapConnServer(conn)
		if err != nil {
			continue
		}
		return wrapped, nil
	}
}
