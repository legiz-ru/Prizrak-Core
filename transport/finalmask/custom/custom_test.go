package custom

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/metacubex/mihomo/transport/finalmask"

	"github.com/stretchr/testify/require"
)

func u64(v uint64) *uint64 { return &v }

func mustSendRecvTCP(t *testing.T, from, to net.Conn, msg []byte) {
	t.Helper()
	writeErr := make(chan error, 1)
	go func() {
		_, err := from.Write(msg)
		writeErr <- err
	}()
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(to, buf); err != nil {
		t.Fatal(err)
	}
	require.Equal(t, msg, buf)
	require.NoError(t, <-writeErr)
}

func tcpPair(t *testing.T, clientCfg, serverCfg *TCPConfig) (net.Conn, net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			accepted <- nil
			return
		}
		accepted <- c
	}()
	clientRaw, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	serverRaw := <-accepted
	require.NotNil(t, serverRaw)
	t.Cleanup(func() { clientRaw.Close(); serverRaw.Close() })

	client, err := clientCfg.WrapConnClient(context.Background(), clientRaw, nil, nil)
	require.NoError(t, err)
	server, err := serverCfg.WrapConnServer(serverRaw)
	require.NoError(t, err)
	_ = client.SetDeadline(time.Now().Add(3 * time.Second))
	_ = server.SetDeadline(time.Now().Add(3 * time.Second))
	return client, server
}

func TestTCPHandshakeRoundTrip(t *testing.T) {
	cfg := &TCPConfig{
		Clients: []*TCPSequence{{Sequence: []*TCPItem{
			{Packet: []byte("cli")},
			{Rand: 2, RandMin: 0x10, RandMax: 0x20},
		}}},
		Servers: []*TCPSequence{{Sequence: []*TCPItem{
			{Packet: []byte("srv")},
			{Rand: 1, RandMin: 0x30, RandMax: 0x40},
		}}},
	}
	client, server := tcpPair(t, cfg, cfg)
	mustSendRecvTCP(t, client, server, []byte("custom tcp payload"))
	mustSendRecvTCP(t, server, client, []byte("custom tcp response"))
	mustSendRecvTCP(t, client, server, []byte{})
	require.True(t, client.(*tcpCustomClientConn).WriterReplaceable())
}

func TestTCPHandshakeReusesCapturedValue(t *testing.T) {
	cfg := &TCPConfig{
		Clients: []*TCPSequence{{Sequence: []*TCPItem{
			{Packet: []byte{0x16, 0x03}},
			{Rand: 4, Save: "nonce"},
		}}},
		Servers: []*TCPSequence{{Sequence: []*TCPItem{
			{Packet: []byte{0x16, 0x03}},
			{Var: "nonce"},
			{Expr: &Expr{Op: "be16", Args: []*ExprArg{{Expr: &Expr{Op: "add", Args: []*ExprArg{{U64: u64(0x1000)}, {U64: u64(1)}}}}}}},
		}}},
	}
	client, server := tcpPair(t, cfg, cfg)
	mustSendRecvTCP(t, client, server, []byte("hello"))
	mustSendRecvTCP(t, server, client, []byte("world"))
}

func TestTCPClientRejectsMismatchedServerSequence(t *testing.T) {
	clientCfg := &TCPConfig{
		Clients: []*TCPSequence{{Sequence: []*TCPItem{{Packet: []byte{0x01}}}}},
		Servers: []*TCPSequence{{Sequence: []*TCPItem{{Packet: []byte{0x02}}}}},
	}
	serverCfg := &TCPConfig{
		Clients: []*TCPSequence{{Sequence: []*TCPItem{{Packet: []byte{0x01}}}}},
		Servers: []*TCPSequence{{Sequence: []*TCPItem{{Packet: []byte{0x03}}}}},
	}
	clientRaw, serverRaw := net.Pipe()
	defer clientRaw.Close()
	defer serverRaw.Close()
	client, err := clientCfg.WrapConnClient(context.Background(), clientRaw, nil, nil)
	require.NoError(t, err)
	server, err := serverCfg.WrapConnServer(serverRaw)
	require.NoError(t, err)
	_ = client.SetDeadline(time.Now().Add(time.Second))
	_ = server.SetDeadline(time.Now().Add(time.Second))

	writeErr := make(chan error, 1)
	go func() {
		_, err := client.Write([]byte("boom"))
		writeErr <- err
	}()
	buf := make([]byte, 4)
	_, readErr := server.Read(buf)
	err = <-writeErr
	require.Error(t, err)
	require.Contains(t, err.Error(), "header auth failed")
	require.Error(t, readErr)
}

func TestTCPServerAnswersErrorSequence(t *testing.T) {
	cfg := &TCPConfig{
		Clients: []*TCPSequence{{Sequence: []*TCPItem{{Packet: []byte("GET / HTTP/1.1\r\n\r\n")}}}},
		Servers: []*TCPSequence{{Sequence: []*TCPItem{{Packet: []byte("HTTP/1.1 101\r\n\r\n")}}}},
		Errors:  []*TCPSequence{{Sequence: []*TCPItem{{Packet: []byte("HTTP/1.1 400\r\n\r\n")}}}},
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			return
		}
		defer raw.Close()
		server, _ := cfg.WrapConnServer(raw)
		_ = server.SetDeadline(time.Now().Add(time.Second))
		_, _ = server.Read(make([]byte, 1))
	}()
	client, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(time.Second))
	_, err = client.Write([]byte("GET /x HTTP/1.1\r\n\r\n"))
	require.NoError(t, err)
	got, _ := io.ReadAll(client)
	require.True(t, strings.HasPrefix(string(got), "HTTP/1.1 400"), "got %q", got)
}

func listenUDP(t *testing.T) net.PacketConn {
	t.Helper()
	c, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { c.Close() })
	return c
}

func mustSendRecvUDP(t *testing.T, from, to net.PacketConn, addr net.Addr, msg []byte) {
	t.Helper()
	go func() {
		_, _ = from.WriteTo(msg, addr)
	}()
	buf := make([]byte, 4096)
	n, _, err := to.ReadFrom(buf)
	require.NoError(t, err)
	require.Equal(t, msg, buf[:n])
}

func TestUDPPrefixRoundTrip(t *testing.T) {
	cfg := &UDPConfig{
		Client: []*UDPItem{{Packet: []byte{0xAA, 0xBB}}, {Rand: 2, RandMin: 0x10, RandMax: 0x20}},
		Server: []*UDPItem{{Packet: []byte{0xCC}}, {Rand: 1, RandMin: 0x30, RandMax: 0x40}},
	}
	clientRaw, serverRaw := listenUDP(t), listenUDP(t)
	client, err := cfg.WrapPacketConnClient(context.Background(), clientRaw, nil, nil)
	require.NoError(t, err)
	server, err := cfg.WrapPacketConnServer(serverRaw)
	require.NoError(t, err)
	_ = client.SetDeadline(time.Now().Add(2 * time.Second))
	_ = server.SetDeadline(time.Now().Add(2 * time.Second))

	mustSendRecvUDP(t, client, server, serverRaw.LocalAddr(), []byte("client -> server"))
	mustSendRecvUDP(t, server, client, clientRaw.LocalAddr(), []byte("server -> client"))
	mustSendRecvUDP(t, client, server, serverRaw.LocalAddr(), []byte{})
}

func TestUDPPrefixWireShape(t *testing.T) {
	cfg := &UDPConfig{
		Client: []*UDPItem{{Packet: []byte{0xAA, 0xBB}}, {Rand: 2, RandMin: 0x10, RandMax: 0x20}},
		Server: []*UDPItem{{Packet: []byte{0xCC}}},
	}
	clientRaw, sniffer := listenUDP(t), listenUDP(t)
	client, err := cfg.WrapPacketConnClient(context.Background(), clientRaw, nil, nil)
	require.NoError(t, err)
	_, err = client.WriteTo([]byte("payload"), sniffer.LocalAddr())
	require.NoError(t, err)
	buf := make([]byte, 64)
	_ = sniffer.SetReadDeadline(time.Now().Add(time.Second))
	n, _, err := sniffer.ReadFrom(buf)
	require.NoError(t, err)
	require.Equal(t, 4+len("payload"), n)
	require.Equal(t, []byte{0xAA, 0xBB}, buf[:2])
	for _, b := range buf[2:4] {
		require.GreaterOrEqual(t, b, byte(0x10))
		require.LessOrEqual(t, b, byte(0x20))
	}
	require.Equal(t, []byte("payload"), buf[4:n])
}

// stunLikeServerConfig computes the mapped address from the client's source;
// the client cannot evaluate metadata on the server's side, so it expects the
// same fields as random bytes and captures them.
func stunLikeClientConfig() *UDPStandaloneConfig {
	return &UDPStandaloneConfig{
		Client: []*UDPItem{
			{Packet: []byte{0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xA4, 0x42}},
			{Rand: 12, RandMin: 0x2A, RandMax: 0x2A, Save: "txid"},
		},
		Server: []*UDPItem{
			{Packet: []byte{0x01, 0x01, 0x00, 0x0C, 0x21, 0x12, 0xA4, 0x42}},
			{Var: "txid"},
			{Packet: []byte{0x00, 0x20, 0x00, 0x08, 0x00, 0x01}},
			{Rand: 2, Save: "mapped_port"},
			{Rand: 4, Save: "mapped_ip"},
		},
	}
}

func stunLikeServerConfig() *UDPStandaloneConfig {
	return &UDPStandaloneConfig{
		Client: []*UDPItem{
			{Packet: []byte{0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xA4, 0x42}},
			{Rand: 12, RandMin: 0x2A, RandMax: 0x2A, Save: "txid"},
		},
		Server: []*UDPItem{
			{Packet: []byte{0x01, 0x01, 0x00, 0x0C, 0x21, 0x12, 0xA4, 0x42}},
			{Var: "txid"},
			{Packet: []byte{0x00, 0x20, 0x00, 0x08, 0x00, 0x01}},
			{Expr: &Expr{Op: "be16", Args: []*ExprArg{{Expr: &Expr{Op: "xor16", Args: []*ExprArg{{Metadata: "src_port_u16"}, {U64: u64(0x2112)}}}}}}},
			{Expr: &Expr{Op: "be32", Args: []*ExprArg{{Expr: &Expr{Op: "xor32", Args: []*ExprArg{{Metadata: "src_ip4_u32"}, {U64: u64(0x2112A442)}}}}}}},
		},
	}
}

func TestUDPStandaloneStunLikeExchange(t *testing.T) {
	clientRaw, serverRaw := listenUDP(t), listenUDP(t)
	client, err := stunLikeClientConfig().WrapPacketConnClient(context.Background(), clientRaw, nil, nil)
	require.NoError(t, err)
	server, err := stunLikeServerConfig().WrapPacketConnServer(serverRaw)
	require.NoError(t, err)
	_ = clientRaw.SetDeadline(time.Now().Add(2 * time.Second))
	_ = serverRaw.SetDeadline(time.Now().Add(2 * time.Second))

	// The server answers the handshake itself; the first payload follows.
	mustSendRecvUDP(t, client, server, serverRaw.LocalAddr(), []byte("first"))
	mustSendRecvUDP(t, client, server, serverRaw.LocalAddr(), []byte("second"))
	mustSendRecvUDP(t, server, client, clientRaw.LocalAddr(), []byte("reply"))
}

func TestUDPStandaloneClientSendsHandshakeBeforePayload(t *testing.T) {
	clientRaw, sniffer := listenUDP(t), listenUDP(t)
	client, err := stunLikeClientConfig().WrapPacketConnClient(context.Background(), clientRaw, nil, nil)
	require.NoError(t, err)
	_ = sniffer.SetReadDeadline(time.Now().Add(2 * time.Second))

	writeDone := make(chan error, 1)
	go func() {
		_, err := client.WriteTo([]byte("payload"), sniffer.LocalAddr())
		writeDone <- err
	}()
	buf := make([]byte, 128)
	n, from, err := sniffer.ReadFrom(buf)
	require.NoError(t, err)
	require.Equal(t, 20, n)
	require.Equal(t, []byte{0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xA4, 0x42}, buf[:8])
	txid := append([]byte(nil), buf[8:20]...)

	// Answer as the server would, with the mapped address of the client.
	port := uint16(from.(*net.UDPAddr).Port) ^ 0x2112
	ip := binary.BigEndian.Uint32(from.(*net.UDPAddr).IP.To4()) ^ 0x2112A442
	resp := append([]byte{0x01, 0x01, 0x00, 0x0C, 0x21, 0x12, 0xA4, 0x42}, txid...)
	resp = append(resp, 0x00, 0x20, 0x00, 0x08, 0x00, 0x01)
	resp = binary.BigEndian.AppendUint16(resp, port)
	resp = binary.BigEndian.AppendUint32(resp, ip)
	_, err = sniffer.WriteTo(resp, from)
	require.NoError(t, err)

	require.NoError(t, <-writeDone)
	n, _, err = sniffer.ReadFrom(buf)
	require.NoError(t, err)
	require.Equal(t, []byte("payload"), buf[:n])
}

func TestEvaluatorOps(t *testing.T) {
	ctx := newEvalContext()
	ctx.vars["a"] = []byte{1, 2, 3, 4}
	cases := []struct {
		expr *Expr
		want []byte
	}{
		{&Expr{Op: "concat", Args: []*ExprArg{{Bytes: []byte{9}}, {Var: "a"}}}, []byte{9, 1, 2, 3, 4}},
		{&Expr{Op: "slice", Args: []*ExprArg{{Var: "a"}, {U64: u64(1)}, {U64: u64(2)}}}, []byte{2, 3}},
		{&Expr{Op: "be16", Args: []*ExprArg{{Expr: &Expr{Op: "xor16", Args: []*ExprArg{{U64: u64(0x1234)}, {U64: u64(0xFFFF)}}}}}}, []byte{0xED, 0xCB}},
		{&Expr{Op: "le32", Args: []*ExprArg{{U64: u64(0x01020304)}}}, []byte{4, 3, 2, 1}},
		{&Expr{Op: "le64", Args: []*ExprArg{{U64: u64(1)}}}, []byte{1, 0, 0, 0, 0, 0, 0, 0}},
		{&Expr{Op: "pad", Args: []*ExprArg{{Bytes: []byte{1}}, {U64: u64(4)}, {Bytes: []byte{0, 7}}}}, []byte{1, 0, 7, 0}},
		{&Expr{Op: "truncate", Args: []*ExprArg{{Var: "a"}, {U64: u64(2)}}}, []byte{1, 2}},
		{&Expr{Op: "be32", Args: []*ExprArg{{Expr: &Expr{Op: "shl", Args: []*ExprArg{{U64: u64(1)}, {U64: u64(8)}}}}}}, []byte{0, 0, 1, 0}},
		{&Expr{Op: "be16", Args: []*ExprArg{{Expr: &Expr{Op: "sub", Args: []*ExprArg{{U64: u64(10)}, {U64: u64(3)}}}}}}, []byte{0, 7}},
	}
	for i, c := range cases {
		got, err := evaluateExpr(c.expr, ctx)
		require.NoError(t, err, "case %d", i)
		b, err := got.asBytes()
		require.NoError(t, err, "case %d", i)
		require.True(t, bytes.Equal(c.want, b), "case %d: got %v", i, b)
	}
	_, err := evaluateExpr(&Expr{Op: "be16", Args: []*ExprArg{{U64: u64(0x10000)}}}, ctx)
	require.Error(t, err)
	_, err = evaluateExpr(&Expr{Op: "sub", Args: []*ExprArg{{U64: u64(1)}, {U64: u64(2)}}}, ctx)
	require.Error(t, err)
	_, err = evaluateExpr(&Expr{Op: "nope", Args: []*ExprArg{{U64: u64(1)}}}, ctx)
	require.Error(t, err)
}

func TestStateStoreExpires(t *testing.T) {
	s := newStateStore(20 * time.Millisecond)
	s.set("k", map[string][]byte{"a": {1}})
	got, ok := s.get("k")
	require.True(t, ok)
	require.Equal(t, []byte{1}, got["a"])
	time.Sleep(40 * time.Millisecond)
	_, ok = s.get("k")
	require.False(t, ok)
}

func TestOptionBuild(t *testing.T) {
	cfg, err := NewTCP(TCPOption{
		Clients: [][]Item{{
			{Packet: "GET / HTTP/1.1\r\n", Type: "str"},
			{Rand: 4, RandRange: rng(0x30, 0x39), Capture: "n"},
			{Packet: "0d0a", Type: "hex"},
		}},
		Servers: [][]Item{{
			{Packet: []any{0x48, 0x54}},
			{Reuse: "n"},
			{Transform: &Transform{Op: "be16", Args: []TransformArg{{Metadata: "dst_port_u16"}}}},
		}},
	})
	require.NoError(t, err)
	require.Len(t, cfg.Clients, 1)
	require.Equal(t, []byte("GET / HTTP/1.1\r\n"), cfg.Clients[0].Sequence[0].Packet)
	require.Equal(t, int32(0x30), cfg.Clients[0].Sequence[1].RandMin)
	require.Equal(t, []byte{0x0d, 0x0a}, cfg.Clients[0].Sequence[2].Packet)
	require.Equal(t, []byte{0x48, 0x54}, cfg.Servers[0].Sequence[0].Packet)
	require.Equal(t, "n", cfg.Servers[0].Sequence[1].Var)
	require.Equal(t, "dst_port_u16", cfg.Servers[0].Sequence[2].Expr.Args[0].Metadata)

	_, err = NewTCP(TCPOption{Clients: [][]Item{{{Packet: "a", Rand: 1}}}})
	require.Error(t, err)
	_, err = NewTCP(TCPOption{Clients: [][]Item{{{Capture: "1bad", Rand: 1}}}})
	require.Error(t, err)

	mask, err := NewUDP(UDPOption{Mode: "standalone", Client: []Item{{Rand: 2}}, Server: []Item{{Rand: 2}}})
	require.NoError(t, err)
	require.IsType(t, &UDPStandaloneConfig{}, mask)
	mask, err = NewUDP(UDPOption{Client: []Item{{Packet: "AQI=", Type: "base64"}}})
	require.NoError(t, err)
	require.Equal(t, []byte{1, 2}, mask.(*UDPConfig).Client[0].Packet)
	_, err = NewUDP(UDPOption{Mode: "nope"})
	require.Error(t, err)
}

func rng(from, to int) *finalmask.Range {
	return &finalmask.Range{From: from, To: to}
}
