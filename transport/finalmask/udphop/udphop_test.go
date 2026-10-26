package udphop

import (
	"context"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/transport/finalmask"

	"github.com/stretchr/testify/require"
)

func TestOption(t *testing.T) {
	c, err := New(Option{Mode: "intervalLocal,intervalRemote", Interval: finalmask.Range{From: 10, To: 20}, RemoteIPs: []string{"10.0.0.0/30", "192.168.1.1"}, RemotePorts: []string{"443", "20000-20003"}})
	require.NoError(t, err)
	require.True(t, c.Local)
	require.True(t, c.Remote)
	require.False(t, c.RemoteOnce)
	require.Equal(t, int64(10), c.IntervalMin)
	require.Equal(t, int64(20), c.IntervalMax)
	require.Len(t, c.RemoteIPs, 2)
	require.Equal(t, []uint16{443, 20000, 20001, 20002, 20003}, c.RemotePorts)

	c, err = New(Option{Mode: "perConnRemote", RemotePorts: []string{"1000"}})
	require.NoError(t, err)
	require.Equal(t, int64(30), c.IntervalMin)

	for _, bad := range []Option{
		{},
		{Mode: "nope"},
		{Mode: "intervalLocal", Interval: finalmask.Range{From: 1, To: 1}},
		{Mode: "intervalRemote"},
		{Mode: "intervalRemote", RemoteIPs: []string{"x"}},
		{Mode: "intervalRemote", RemotePorts: []string{"70000"}},
	} {
		_, err := New(bad)
		require.Error(t, err, "%+v", bad)
	}
}

func TestRandPrefix(t *testing.T) {
	p := netip.MustParsePrefix("10.1.2.0/24")
	for i := 0; i < 50; i++ {
		require.True(t, p.Contains(randPrefix(p)))
	}
	p = netip.MustParsePrefix("2001:db8::/32")
	for i := 0; i < 50; i++ {
		require.True(t, p.Contains(randPrefix(p)))
	}
	require.Equal(t, netip.MustParseAddr("1.2.3.4"), randPrefix(netip.MustParsePrefix("1.2.3.4/32")))
}

func TestHopKeepsExchangingPackets(t *testing.T) {
	server, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer server.Close()

	var dials atomic.Int32
	dialer := &finalmask.Dialer{
		DialUDP: func(ctx context.Context, addr string) (net.PacketConn, net.Addr, error) {
			dials.Add(1)
			udpAddr, err := net.ResolveUDPAddr("udp", addr)
			if err != nil {
				return nil, nil, err
			}
			conn, err := net.ListenPacket("udp", "127.0.0.1:0")
			return conn, udpAddr, err
		},
	}
	cfg := &Config{Local: true, IntervalMin: 5, IntervalMax: 5}
	dest, _ := finalmask.ParseDestination(server.LocalAddr().String())
	conn, err := NewConn(context.Background(), cfg, &dest, dialer)
	require.NoError(t, err)
	defer conn.Close()
	hop := conn.(*hopConn)

	echo := func() {
		_, err := conn.WriteTo([]byte("ping"), nil)
		require.NoError(t, err)
		buf := make([]byte, 64)
		_ = server.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, from, err := server.ReadFrom(buf)
		require.NoError(t, err)
		require.Equal(t, "ping", string(buf[:n]))
		_, err = server.WriteTo([]byte("pong"), from)
		require.NoError(t, err)
		n, _, err = conn.ReadFrom(buf)
		require.NoError(t, err)
		require.Equal(t, "pong", string(buf[:n]))
	}
	echo()
	first := conn.LocalAddr().String()
	hop.hop()
	require.Equal(t, int32(2), dials.Load())
	require.NotEqual(t, first, conn.LocalAddr().String())
	echo()
	hop.hop()
	echo()
}

func TestRemoteOncePicksAddress(t *testing.T) {
	var dialed string
	dialer := &finalmask.Dialer{
		DialUDP: func(ctx context.Context, addr string) (net.PacketConn, net.Addr, error) {
			dialed = addr
			udpAddr, _ := net.ResolveUDPAddr("udp", addr)
			conn, err := net.ListenPacket("udp", "127.0.0.1:0")
			return conn, udpAddr, err
		},
	}
	cfg, err := New(Option{Mode: "perConnRemote", RemoteIPs: []string{"127.0.0.0/8"}, RemotePorts: []string{"40000-40010"}})
	require.NoError(t, err)
	dest := finalmask.Destination{Host: "example.com", Port: 443}
	conn, err := cfg.WrapPacketConnClient(context.Background(), nil, &dest, dialer)
	require.NoError(t, err)
	defer conn.Close()
	host, port, err := net.SplitHostPort(dialed)
	require.NoError(t, err)
	require.True(t, netip.MustParsePrefix("127.0.0.0/8").Contains(netip.MustParseAddr(host)))
	require.GreaterOrEqual(t, port, "40000")
	require.LessOrEqual(t, port, "40010")
	require.Equal(t, dest.Addr(), dialed)
}
