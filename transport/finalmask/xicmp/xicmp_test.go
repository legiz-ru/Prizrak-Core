package xicmp

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	"github.com/metacubex/mihomo/transport/finalmask"

	"github.com/stretchr/testify/require"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// fakeSocket is an ICMP socket whose peer is the test: every echo request
// written to it is parsed, and the test answers with echo replies.
type fakeSocket struct {
	proto  int
	writes chan []byte
	reads  chan []byte
	closed chan struct{}
}

func newFakeSocket(proto int) *fakeSocket {
	return &fakeSocket{proto: proto, writes: make(chan []byte, 16), reads: make(chan []byte, 16), closed: make(chan struct{})}
}

func (s *fakeSocket) ReadFrom(b []byte) (int, net.Addr, error) {
	select {
	case p := <-s.reads:
		return copy(b, p), &net.IPAddr{IP: net.IPv4(10, 0, 0, 1)}, nil
	case <-s.closed:
		return 0, nil, net.ErrClosed
	}
}

func (s *fakeSocket) WriteTo(b []byte, _ net.Addr) (int, error) {
	s.writes <- append([]byte(nil), b...)
	return len(b), nil
}

func (s *fakeSocket) Close() error                     { close(s.closed); return nil }
func (s *fakeSocket) SetDeadline(time.Time) error      { return nil }
func (s *fakeSocket) SetReadDeadline(time.Time) error  { return nil }
func (s *fakeSocket) SetWriteDeadline(time.Time) error { return nil }

func TestChecksumMatchesXNet(t *testing.T) {
	for _, data := range [][]byte{nil, {1}, {1, 2, 3}, bytes.Repeat([]byte{0xff}, 100)} {
		msg := icmp.Message{Type: ipv4.ICMPTypeEcho, Body: &icmp.Echo{ID: 65535, Seq: 1, Data: data}}
		want, err := msg.Marshal(nil)
		require.NoError(t, err)
		b := make([]byte, 8+len(data))
		copy(b[8:], data)
		got := marshal(b, ipv4.ICMPTypeEcho, 65535, 1, len(data))
		require.Equal(t, want, got)
	}
	b := make([]byte, 8)
	got := marshal(b, ipv6.ICMPTypeEchoRequest, 65535, 65537, 0)
	require.Equal(t, []byte{128, 0, 0, 0, 255, 255, 0, 1}, got)
}

func TestClientExchangesEchoes(t *testing.T) {
	s4, s6 := newFakeSocket(1), newFakeSocket(58)
	old := listenICMP
	listenICMP = func(bool) (icmpSocket, icmpSocket, error) { return s4, s6, nil }
	defer func() { listenICMP = old }()

	cfg, err := New(Config{IPs: []string{"10.0.0.1"}})
	require.NoError(t, err)
	dest := finalmask.Destination{Host: "example.com", Port: 443}
	conn, err := cfg.WrapPacketConnClient(context.Background(), nil, &dest, nil)
	require.NoError(t, err)
	defer conn.Close()
	client := conn.(*clientConn)

	payload := []byte("quic initial")
	_, err = conn.WriteTo(payload, nil)
	require.NoError(t, err)
	wire := <-s4.writes
	msg, err := icmp.ParseMessage(1, wire)
	require.NoError(t, err)
	require.Equal(t, ipv4.ICMPTypeEcho, msg.Type)
	echo := msg.Body.(*icmp.Echo)
	require.Equal(t, client.id, echo.ID)
	require.Equal(t, client.clientID[:], echo.Data[:8])
	require.Equal(t, payload, echo.Data[8:])

	// The server's reply carries the payload alone.
	reply, err := (&icmp.Message{Type: ipv4.ICMPTypeEchoReply, Body: &icmp.Echo{ID: client.id, Seq: echo.Seq, Data: []byte("server data")}}).Marshal(nil)
	require.NoError(t, err)
	s4.reads <- reply
	// A reply to another process, and our own request reflected, are ignored.
	other, _ := (&icmp.Message{Type: ipv4.ICMPTypeEchoReply, Body: &icmp.Echo{ID: client.id + 1, Seq: 1, Data: []byte("x")}}).Marshal(nil)
	s4.reads <- other
	reflected, _ := (&icmp.Message{Type: ipv4.ICMPTypeEchoReply, Body: &icmp.Echo{ID: client.id, Seq: 1, Data: echo.Data}}).Marshal(nil)
	s4.reads <- reflected

	buf := make([]byte, 64)
	n, from, err := conn.ReadFrom(buf)
	require.NoError(t, err)
	require.Equal(t, "server data", string(buf[:n]))
	require.IsType(t, &net.UDPAddr{}, from)

	// Nothing else should come through.
	done := make(chan struct{})
	go func() {
		_, _, _ = conn.ReadFrom(buf)
		close(done)
	}()
	select {
	case <-done:
		t.Fatal("unexpected packet delivered")
	case <-time.After(100 * time.Millisecond):
	}
	require.NoError(t, conn.Close())
	<-done
}

func TestDomainNeedsIPs(t *testing.T) {
	cfg, err := New(Config{})
	require.NoError(t, err)
	dest := finalmask.Destination{Host: "example.com", Port: 443}
	_, err = cfg.WrapPacketConnClient(context.Background(), nil, &dest, nil)
	require.Error(t, err)
	_, err = New(Config{IPs: []string{"nope"}})
	require.Error(t, err)
}
