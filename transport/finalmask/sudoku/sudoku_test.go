package sudoku

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func configs() []Config {
	return []Config{
		{Password: "sudoku-mask"},
		{Password: "sudoku-mask", ASCII: "prefer_ascii", PaddingMin: 10, PaddingMax: 30},
		{Password: "sudoku-mask", CustomTable: "xpxvvpvv"},
		{Password: "sudoku-mask", CustomTables: []string{"xpxvvpvv", "vxpvxvvp"}, PaddingMin: 100, PaddingMax: 100},
	}
}

func TestConfig(t *testing.T) {
	for _, c := range configs() {
		_, err := New(c)
		require.NoError(t, err)
	}
	for _, bad := range []Config{
		{ASCII: "nope"},
		{CustomTable: "xxxxxxxx"},
		{CustomTable: "xpv"},
		{CustomTables: []string{"xpxvvpvv", "abcdefgh"}},
	} {
		_, err := New(bad)
		require.Error(t, err, "%+v", bad)
	}
}

func TestCodecRoundTrip(t *testing.T) {
	for _, c := range configs() {
		tables, err := getTables(&c)
		require.NoError(t, err)
		pMin, pMax := normalizedPadding(&c)
		data := make([]byte, 3000)
		_, _ = rand.Read(data)
		encoded, err := newCodec(tables, pMin, pMax).encode(data)
		require.NoError(t, err)
		tableIndex := 0
		hints, decoded, err := decodeBytes(tables, &tableIndex, encoded, nil, nil)
		require.NoError(t, err)
		require.Empty(t, hints)
		require.Equal(t, data, decoded)

		enc := newPackedEncoder(tables, pMin, pMax)
		packed, err := enc.encode(data)
		require.NoError(t, err)
		_, _, _, out, err := decodePackedBytes(tablesToLayouts(tables), packed, 0, 0, 0, nil)
		require.NoError(t, err)
		require.Equal(t, data, out)
		require.Less(t, len(packed), len(encoded))
	}
}

func TestASCIIModeStaysPrintable(t *testing.T) {
	c := Config{Password: "p", ASCII: "ascii", PaddingMin: 50, PaddingMax: 50}
	tables, err := getTables(&c)
	require.NoError(t, err)
	data := make([]byte, 512)
	_, _ = rand.Read(data)
	encoded, err := newCodec(tables, 50, 50).encode(data)
	require.NoError(t, err)
	for _, b := range encoded {
		require.True(t, b == '\n' || (b >= 0x20 && b < 0x7f), "byte %x", b)
	}
}

func tcpPair(t *testing.T, c *Config) (net.Conn, net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			accepted <- nil
			return
		}
		accepted <- conn
	}()
	clientRaw, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	serverRaw := <-accepted
	require.NotNil(t, serverRaw)
	t.Cleanup(func() { clientRaw.Close(); serverRaw.Close() })
	client, err := c.WrapConnClient(context.Background(), clientRaw, nil, nil)
	require.NoError(t, err)
	server, err := c.WrapConnServer(serverRaw)
	require.NoError(t, err)
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	_ = server.SetDeadline(time.Now().Add(5 * time.Second))
	return client, server
}

func TestTCPRoundTrip(t *testing.T) {
	for _, c := range configs() {
		cfg, err := New(c)
		require.NoError(t, err)
		client, server := tcpPair(t, cfg)
		for _, size := range []int{1, 17, 1500, 70000} {
			up := make([]byte, size)
			_, _ = rand.Read(up)
			down := make([]byte, size)
			_, _ = rand.Read(down)
			go func() {
				_, _ = client.Write(up)
			}()
			got := make([]byte, size)
			_, err := io.ReadFull(server, got)
			require.NoError(t, err)
			require.True(t, bytes.Equal(up, got))
			go func() {
				_, _ = server.Write(down)
			}()
			_, err = io.ReadFull(client, got)
			require.NoError(t, err)
			require.True(t, bytes.Equal(down, got))
		}
		require.Error(t, func() error {
			if cw, ok := client.(interface{ CloseWrite() error }); ok {
				_ = cw.CloseWrite()
				_, err := server.Read(make([]byte, 1))
				return err
			}
			return nil
		}())
	}
}

func TestUDPRoundTrip(t *testing.T) {
	for _, c := range configs() {
		cfg, err := New(c)
		require.NoError(t, err)
		clientRaw, err := net.ListenPacket("udp", "127.0.0.1:0")
		require.NoError(t, err)
		serverRaw, err := net.ListenPacket("udp", "127.0.0.1:0")
		require.NoError(t, err)
		client, err := cfg.WrapPacketConnClient(context.Background(), clientRaw, nil, nil)
		require.NoError(t, err)
		server, err := cfg.WrapPacketConnServer(serverRaw)
		require.NoError(t, err)
		_ = client.SetDeadline(time.Now().Add(2 * time.Second))
		_ = server.SetDeadline(time.Now().Add(2 * time.Second))
		for _, msg := range [][]byte{[]byte("client -> server"), make([]byte, 700), {}} {
			_, _ = rand.Read(msg)
			_, err = client.WriteTo(msg, serverRaw.LocalAddr())
			require.NoError(t, err)
			buf := make([]byte, 4096)
			n, from, err := server.ReadFrom(buf)
			require.NoError(t, err)
			require.Equal(t, msg, buf[:n])
			_, err = server.WriteTo(msg, from)
			require.NoError(t, err)
			n, _, err = client.ReadFrom(buf)
			require.NoError(t, err)
			require.Equal(t, msg, buf[:n])
		}
		client.Close()
		server.Close()
	}
}
