package xdns

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/net/dns/dnsmessage"
)

// The compact spelling of the first xdns client: the zone, the record type
// and the resolver in one string, built into the client of that time.
func TestParseCompactResolvers(t *testing.T) {
	cfg, ok, err := ParseCompact(map[string]any{
		"resolvers": []any{
			"auth.example.com:aaaa+udp://77.88.8.8:53",
			"auth.example.com:AAAA+udp://8.8.8.8",
			"t.example.com+udp://1.1.1.1",
			"t.example.com:a+tcp://9.9.9.9:53",
		},
	})
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, []LegacyResolver{
		{Zone: "auth.example.com", Type: TypeAAAA, Resolver: ResolverConfig{Type: "udp", Addr: "77.88.8.8:53"}},
		{Zone: "auth.example.com", Type: TypeAAAA, Resolver: ResolverConfig{Type: "udp", Addr: "8.8.8.8:53"}},
		{Zone: "t.example.com", Type: TypeTXT, Resolver: ResolverConfig{Type: "udp", Addr: "1.1.1.1:53"}},
		{Zone: "t.example.com", Type: TypeA, Resolver: ResolverConfig{Type: "tcp", Addr: "9.9.9.9:53"}},
	}, cfg.Resolvers)
}

// Structured settings are the current xdns and are left to it.
func TestParseCompactLeavesStructuredSettingsAlone(t *testing.T) {
	_, ok, err := ParseCompact(map[string]any{
		"domains":   []any{map[string]any{"names": []any{"t.example.com"}}},
		"resolvers": []any{map[string]any{"addrs": []any{"1.1.1.1"}}},
	})
	require.NoError(t, err)
	require.False(t, ok)
}

func TestParseCompactRejects(t *testing.T) {
	for spec, want := range map[string]string{
		"bad://127.0.0.1:53":           "invalid resolver scheme",
		"t.example.com+quic://1.1.1.1": "unknown resolver scheme",
		"t.example.com+udp://":         "empty resolver server",
		"t.example.com:mx+udp://1.1.1": "unsupported method",
		":aaaa+udp://1.1.1.1":          "empty domain",
	} {
		_, ok, err := ParseCompact(map[string]any{"resolvers": []any{spec}})
		require.True(t, ok, spec)
		require.Error(t, err, spec)
		require.Contains(t, err.Error(), want, spec)
	}
	// The two spellings are two protocols.
	_, _, err := ParseCompact(map[string]any{"resolvers": []any{
		"t.example.com+udp://1.1.1.1",
		map[string]any{"addrs": []any{"udp://8.8.8.8:53"}},
	}})
	require.ErrorContains(t, err, "write all entries one way")
	_, _, err = ParseCompact(map[string]any{"resolvers": []any{"t.example.com+udp://1.1.1.1"}, "extra-poll": 1})
	require.ErrorContains(t, err, "extra-poll belongs to the current xdns")
	_, _, err = ParseCompact(map[string]any{"domains": []any{"t.example.com:mx"}})
	require.ErrorContains(t, err, "unsupported method")
}

// Only the client of the first xdns is ported.
func TestLegacyServerSideIsRefused(t *testing.T) {
	cfg, ok, err := ParseCompact(map[string]any{"domains": []any{"t.example.com:aaaa"}})
	require.NoError(t, err)
	require.True(t, ok)
	_, err = cfg.WrapPacketConnServer(nil)
	require.ErrorContains(t, err, "is not ported")
}

// legacyEchoServer answers queries the way the first xdns server does,
// sending back each packet it got from a client, in TXT, A or AAAA records
// as the query asks.
func legacyEchoServer(t *testing.T, zone string) string {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	go func() {
		pending := map[[8]byte][][]byte{}
		buf := make([]byte, 4096)
		for {
			n, addr, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			var msg dnsmessage.Message
			if msg.Unpack(buf[:n]) != nil || len(msg.Questions) != 1 {
				continue
			}
			q := msg.Questions[0]
			name := strings.TrimSuffix(strings.ToLower(q.Name.String()), "."+zone+".")
			raw, err := legacyBase32.DecodeString(strings.ToUpper(strings.ReplaceAll(name, ".", "")))
			if err != nil || len(raw) < 9 || raw[8] < legacyMaxPacket {
				continue
			}
			var id [8]byte
			copy(id[:], raw)
			rest := raw[9+int(raw[8]-legacyMaxPacket):]
			if len(rest) > 0 && int(rest[0]) == len(rest)-1 {
				pending[id] = append(pending[id], append([]byte(nil), rest[1:]...))
			}
			var payload []byte
			for _, p := range pending[id] {
				payload = binary.BigEndian.AppendUint16(payload, uint16(len(p)))
				payload = append(payload, p...)
			}
			delete(pending, id)
			resp := dnsmessage.Message{
				Header:    dnsmessage.Header{ID: msg.ID, Response: true, Authoritative: true},
				Questions: msg.Questions,
			}
			rh := dnsmessage.ResourceHeader{Name: q.Name, Type: q.Type, Class: q.Class, TTL: 60}
			switch q.Type {
			case dnsmessage.TypeTXT:
				var strs []string
				for p := payload; len(p) > 0; {
					size := len(p)
					if size > 255 {
						size = 255
					}
					strs = append(strs, string(p[:size]))
					p = p[size:]
				}
				if strs == nil {
					strs = []string{""}
				}
				resp.Answers = append(resp.Answers, dnsmessage.Resource{Header: rh, Body: &dnsmessage.TXTResource{TXT: strs}})
			case dnsmessage.TypeA, dnsmessage.TypeAAAA:
				size := 4
				if q.Type == dnsmessage.TypeAAAA {
					size = 16
				}
				chunk := size - legacyIPHeader
				records := (len(payload) + chunk - 1) / chunk
				if records == 0 {
					records = 1
				}
				for i := 0; i < records; i++ {
					data := make([]byte, size)
					part := payload[i*chunk:]
					if len(part) > chunk {
						part = part[:chunk]
					}
					data[0], data[1] = byte(i), byte(len(part))
					copy(data[legacyIPHeader:], part)
					var body dnsmessage.ResourceBody
					if size == 4 {
						r := &dnsmessage.AResource{}
						copy(r.A[:], data)
						body = r
					} else {
						r := &dnsmessage.AAAAResource{}
						copy(r.AAAA[:], data)
						body = r
					}
					// Shuffled order: the index puts the chunks back.
					resp.Answers = append([]dnsmessage.Resource{{Header: rh, Body: body}}, resp.Answers...)
				}
			}
			out, err := resp.Pack()
			if err == nil {
				_, _ = conn.WriteTo(out, addr)
			}
		}
	}()
	return conn.LocalAddr().String()
}

func TestLegacyClientRoundTrip(t *testing.T) {
	for _, method := range []string{"txt", "a", "aaaa"} {
		method := method
		t.Run(method, func(t *testing.T) {
			addr := legacyEchoServer(t, "t.example.com")
			cfg, ok, err := ParseCompact(map[string]any{"resolvers": []any{
				"t.example.com:" + method + "+udp://" + addr,
				"t.example.com:" + method + "+udp://" + addr,
			}})
			require.NoError(t, err)
			require.True(t, ok)
			conn, err := cfg.WrapPacketConnClient(context.Background(), nil, nil, localDialer())
			require.NoError(t, err)
			defer conn.Close()

			for _, size := range []int{1, 77, 120} { // 120 is about the most a query name has room for
				p := make([]byte, size)
				_, _ = rand.Read(p)
				_, err := conn.WriteTo(p, nil)
				require.NoError(t, err)
				buf := make([]byte, 4096)
				n, _, err := readWithTimeout(conn, buf, 10*time.Second)
				require.NoError(t, err, "size %d", size)
				require.True(t, bytes.Equal(p, buf[:n]), "size %d", size)
			}
			_, err = conn.WriteTo(make([]byte, legacyMaxPacket), nil)
			require.ErrorContains(t, err, "does not fit")
		})
	}
}
