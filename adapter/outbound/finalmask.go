package outbound

import (
	"context"
	"errors"
	"fmt"
	"net"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/finalmask"
	"github.com/metacubex/mihomo/transport/finalmask/option"
	"github.com/metacubex/mihomo/transport/tuic/common"

	"github.com/metacubex/quic-go"
	"github.com/metacubex/tls"
)

// FinalMaskOption is the finalmask block of a vless or trojan proxy, see
// option.Option.
type FinalMaskOption = option.Option

// newFinalMaskDialer opens the sockets the masks ask for through the proxy's
// own dialer, so interface binding, routing marks and dialer-proxy apply.
func newFinalMaskDialer(d C.Dialer) *finalmask.Dialer {
	return &finalmask.Dialer{
		DialTCP: func(ctx context.Context, addr string) (net.Conn, error) {
			return d.DialContext(ctx, "tcp", addr)
		},
		DialUDP: func(ctx context.Context, addr string) (net.PacketConn, net.Addr, error) {
			conn, err := d.DialContext(ctx, "udp", addr)
			if err != nil {
				return nil, nil, err
			}
			return &connectedPacketConn{Conn: conn}, conn.RemoteAddr(), nil
		},
	}
}

// connectedPacketConn gives a connected UDP socket the PacketConn interface
// the masks and QUIC want; WriteTo ignores the address, the socket has one.
type connectedPacketConn struct {
	net.Conn
}

func (c *connectedPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, err := c.Conn.Read(p)
	return n, c.Conn.RemoteAddr(), err
}

func (c *connectedPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	return c.Conn.Write(p)
}

func (c *connectedPacketConn) SetReadBuffer(bytes int) error {
	if rb, ok := c.Conn.(interface{ SetReadBuffer(int) error }); ok {
		return rb.SetReadBuffer(bytes)
	}
	return nil
}

func (c *connectedPacketConn) SetWriteBuffer(bytes int) error {
	if wb, ok := c.Conn.(interface{ SetWriteBuffer(int) error }); ok {
		return wb.SetWriteBuffer(bytes)
	}
	return nil
}

// finalMaskDialTCP dials addr and wraps the connection in the TCP chain.
func finalMaskDialTCP(ctx context.Context, fm *finalmask.FinalMask, d C.Dialer, fmDialer *finalmask.Dialer, addr string) (net.Conn, error) {
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	if !fm.HasTCP() {
		return conn, nil
	}
	dest, err := finalmask.ParseDestination(addr)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return fm.WrapConnClient(ctx, conn, &dest, fmDialer)
}

// finalMaskDialQUIC opens a QUIC connection over the UDP chain, as
// common.DialQuic does over a plain socket.
func finalMaskDialQUIC(ctx context.Context, fm *finalmask.FinalMask, fmDialer *finalmask.Dialer, addr string, tlsConf *tls.Config, conf *quic.Config, option common.DialQuicOption) (*quic.Conn, error) {
	dest, err := finalmask.ParseDestination(addr)
	if err != nil {
		return nil, err
	}
	pc, raddr, err := fm.DialUDP(ctx, dest, fmDialer)
	if err != nil {
		return nil, err
	}
	transport := quic.Transport{
		Conn:               pc,
		ConnectionIDLength: option.ConnectionIDLength,
	}
	transport.SetCreatedConn(true) // auto close conn
	transport.SetSingleUse(true)   // auto close transport
	var quicConn *quic.Conn
	if option.Early {
		quicConn, err = transport.DialEarly(ctx, raddr, tlsConf, conf)
	} else {
		quicConn, err = transport.Dial(ctx, raddr, tlsConf, conf)
	}
	if err != nil {
		_ = transport.Close()
		_ = pc.Close()
		return nil, err
	}
	return quicConn, nil
}

// checkFinalMaskNetwork refuses UDP masks where no transport would use them:
// VLESS over mKCP and xhttp over HTTP/3 are the UDP transports.
func checkFinalMaskNetwork(fm *finalmask.FinalMask, proxyType, network string, alpn []string) error {
	if !fm.HasUDP() {
		return nil
	}
	if proxyType == "vless" && (network == "mkcp" || network == "kcp") {
		return nil
	}
	if proxyType != "vless" || network != "xhttp" {
		return fmt.Errorf("finalmask.udp is used by mkcp and by xhttp over HTTP/3 only (type: vless, network: mkcp or network: xhttp with alpn: [h3]), not by %s over %s", proxyType, defaultNetwork(network))
	}
	if len(alpn) != 1 || alpn[0] != "h3" {
		return errors.New("finalmask.udp is used by mkcp and by xhttp over HTTP/3 only, set alpn: [h3]")
	}
	return nil
}

func defaultNetwork(network string) string {
	if network == "" {
		return "tcp"
	}
	return network
}
