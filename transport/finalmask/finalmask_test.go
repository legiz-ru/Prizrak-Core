package finalmask_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"net"
	"testing"
	"time"

	"github.com/metacubex/mihomo/transport/finalmask"
	"github.com/metacubex/mihomo/transport/finalmask/custom"
	"github.com/metacubex/mihomo/transport/finalmask/fragment"
	"github.com/metacubex/mihomo/transport/finalmask/noise"
	"github.com/metacubex/mihomo/transport/finalmask/sudoku"
	"github.com/metacubex/mihomo/transport/finalmask/xdns"

	"github.com/stretchr/testify/require"
)

func localDialer() *finalmask.Dialer {
	return &finalmask.Dialer{
		DialTCP: func(ctx context.Context, addr string) (net.Conn, error) {
			return net.Dial("tcp", addr)
		},
		DialUDP: func(ctx context.Context, addr string) (net.PacketConn, net.Addr, error) {
			udpAddr, err := net.ResolveUDPAddr("udp", addr)
			if err != nil {
				return nil, nil, err
			}
			conn, err := net.ListenPacket("udp", "127.0.0.1:0")
			return conn, udpAddr, err
		},
	}
}

func tcpChain(t *testing.T) *finalmask.FinalMask {
	t.Helper()
	frag, err := fragment.New(fragment.Option{Packets: "1-2", Length: finalmask.Range{From: 10, To: 20}})
	require.NoError(t, err)
	sud, err := sudoku.New(sudoku.Config{Password: "chain"})
	require.NoError(t, err)
	hdr, err := custom.NewTCP(custom.TCPOption{
		Clients: [][]custom.Item{{{Packet: "hello", Type: "str"}}},
		Servers: [][]custom.Item{{{Packet: "world", Type: "str"}}},
	})
	require.NoError(t, err)
	fm, err := finalmask.New([]finalmask.TCPMask{hdr, sud, frag}, nil)
	require.NoError(t, err)
	return fm
}

// The same chain on both ends carries a stream through a listener and a
// dial, whatever the order of the masks is as long as it is the same.
func TestTCPChainThroughListener(t *testing.T) {
	fm := tcpChain(t)
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	ln := finalmask.NewListener(raw, fm)
	defer ln.Close()

	payload := make([]byte, 100*1024)
	_, _ = rand.Read(payload)
	served := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			served <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
		buf := make([]byte, len(payload))
		if _, err := io.ReadFull(conn, buf); err != nil {
			served <- err
			return
		}
		_, err = conn.Write(buf)
		served <- err
	}()

	dest, err := finalmask.ParseDestination(raw.Addr().String())
	require.NoError(t, err)
	conn, err := fm.DialTCP(context.Background(), dest, localDialer())
	require.NoError(t, err)
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	go func() { _, _ = conn.Write(payload) }()
	got := make([]byte, len(payload))
	_, err = io.ReadFull(conn, got)
	require.NoError(t, err)
	require.True(t, bytes.Equal(payload, got))
	require.NoError(t, <-served)
}

// A listener survives a connection its chain refuses: the next client gets
// through, and a plain client does not reach the stream.
func TestListenerKeepsAcceptingAfterBadPeer(t *testing.T) {
	fm := tcpChain(t)
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	ln := finalmask.NewListener(raw, fm)
	defer ln.Close()

	results := make(chan string, 2)
	go func() {
		for i := 0; i < 2; i++ {
			conn, err := ln.Accept()
			if err != nil {
				results <- "accept: " + err.Error()
				return
			}
			go func() {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
				buf := make([]byte, 4)
				if _, err := io.ReadFull(conn, buf); err != nil {
					results <- "bad"
					return
				}
				results <- string(buf)
			}()
		}
	}()

	plain, err := net.Dial("tcp", raw.Addr().String())
	require.NoError(t, err)
	_, _ = plain.Write([]byte("junk that is not the header"))
	defer plain.Close()

	dest, _ := finalmask.ParseDestination(raw.Addr().String())
	good, err := fm.DialTCP(context.Background(), dest, localDialer())
	require.NoError(t, err)
	defer good.Close()
	_, err = good.Write([]byte("ping"))
	require.NoError(t, err)

	seen := map[string]bool{}
	for i := 0; i < 2; i++ {
		select {
		case r := <-results:
			seen[r] = true
		case <-time.After(5 * time.Second):
			t.Fatal("timeout")
		}
	}
	require.True(t, seen["ping"], "%v", seen)
	require.True(t, seen["bad"], "%v", seen)
}

func TestUDPChainOrder(t *testing.T) {
	n, err := noise.New(noise.Option{Noise: []noise.ItemOption{{Rand: finalmask.Range{From: 8, To: 8}}}})
	require.NoError(t, err)
	x, err := xdns.New(xdns.Option{
		Domains:   []xdns.DomainOption{{Names: []string{"t.example.com"}}},
		Resolvers: []xdns.ResolverOption{{Addrs: []string{"127.0.0.1:1"}}},
	})
	require.NoError(t, err)
	_, err = finalmask.New(nil, []finalmask.UDPMask{x, n})
	require.Error(t, err, "a mask that opens the network must be last")
	fm, err := finalmask.New(nil, []finalmask.UDPMask{n, x})
	require.NoError(t, err)
	require.True(t, fm.HasUDP())
	require.False(t, fm.HasTCP())
	require.False(t, (*finalmask.FinalMask)(nil).HasUDP())
}

func TestRange(t *testing.T) {
	var r finalmask.Range
	require.NoError(t, r.UnmarshalText([]byte("10-20")))
	require.Equal(t, finalmask.Range{From: 10, To: 20}, r)
	require.NoError(t, r.UnmarshalText([]byte("7")))
	require.Equal(t, finalmask.Range{From: 7, To: 7}, r)
	require.NoError(t, r.UnmarshalText([]byte("-5--1")))
	require.Equal(t, finalmask.Range{From: -5, To: -1}, r)
	require.NoError(t, r.UnmarshalText([]byte("")))
	require.True(t, r.IsZero())
	require.Error(t, r.UnmarshalText([]byte("a-b")))
	require.Equal(t, "10-20", finalmask.Range{From: 10, To: 20}.String())

	for i := 0; i < 100; i++ {
		v := finalmask.RandBetween(5, 8)
		require.GreaterOrEqual(t, v, int64(5))
		require.Less(t, v, int64(8))
	}
	require.Equal(t, int64(5), finalmask.RandBetween(5, 5))
	require.Equal(t, int64(5), finalmask.RandBetween(5, 6))
	b := make([]byte, 256)
	finalmask.RandBytesBetween(b, 'a', 'f')
	for _, c := range b {
		require.True(t, c >= 'a' && c <= 'f')
	}
}
