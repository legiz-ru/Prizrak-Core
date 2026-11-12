package xdns

import (
	"bytes"
	"context"
	"crypto/rand"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/metacubex/mihomo/transport/finalmask"

	"github.com/stretchr/testify/require"
	"golang.org/x/net/dns/dnsmessage"
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

func TestDomain(t *testing.T) {
	d, err := NewDomain("t.example.com", 255, 63, []uint16{TypeTXT}, 0)
	require.NoError(t, err)
	require.True(t, d.IsDomain(dnsmessage.MustNewName("abc.T.Example.com.")))
	require.False(t, d.IsDomain(dnsmessage.MustNewName("t.example.com.")))
	require.True(t, d.IsApex(dnsmessage.MustNewName("t.example.com.")))
	require.False(t, d.IsDomain(dnsmessage.MustNewName("nott.example.com.")))

	data := make([]byte, d.cap)
	_, _ = rand.Read(data)
	name := d.Encode(data)
	require.LessOrEqual(t, int(name.Length), 255)
	var decoded [255]byte
	n := d.Decode(&decoded, name)
	require.Equal(t, data, decoded[:n])

	_, err = NewDomain("bücher.example", 255, 63, []uint16{TypeTXT}, 0)
	require.NoError(t, err)
	for _, bad := range []struct {
		name            string
		lenLimit, label int
	}{
		{"", 255, 63},
		{"a..b", 255, 63},
		{"example.com", 20, 63},
		{"example.com", 255, 64},
	} {
		_, err := NewDomain(bad.name, bad.lenLimit, bad.label, []uint16{TypeTXT}, 0)
		require.Error(t, err, "%+v", bad)
	}
}

func TestRespRoundTrip(t *testing.T) {
	d, err := NewDomain("t.example.com", 255, 63, []uint16{TypeA, TypeCNAME, TypeTXT, TypeAAAA}, 0)
	require.NoError(t, err)
	for _, qtype := range []uint16{TypeA, TypeCNAME, TypeTXT, TypeAAAA} {
		query := dnsmessage.Message{
			Header:    dnsmessage.Header{ID: 7},
			Questions: []dnsmessage.Question{{Name: d.Encode([]byte("poll")), Type: dnsmessage.Type(qtype), Class: dnsmessage.ClassINET}},
		}
		r := NewResp(query, d, 0)
		require.Greater(t, r.cap, 0, "type %d", qtype)
		data := make([]byte, r.cap)
		_, _ = rand.Read(data)
		packed := r.Encode(nil, data)
		require.LessOrEqual(t, len(packed), 512, "type %d", qtype)

		var answer dnsmessage.Message
		require.NoError(t, answer.Unpack(packed))
		out := make([]byte, 4096)
		n := NewResp(answer, d, 0).Decode(out)
		require.Equal(t, data, out[:n], "type %d", qtype)

		// A payload that does not fit the caller's buffer is rejected.
		require.Equal(t, 0, NewResp(answer, d, 0).Decode(make([]byte, 10)))
	}
}

func TestParseResolver(t *testing.T) {
	r, err := ParseResolver("1.1.1.1")
	require.NoError(t, err)
	require.Equal(t, ResolverConfig{Type: "udp", Addr: "1.1.1.1:53", Worker: 32}, r)
	r, err = ParseResolver("tcp://[2606:4700::1111]:5353")
	require.NoError(t, err)
	require.Equal(t, ResolverConfig{Type: "tcp", Addr: "[2606:4700::1111]:5353", Worker: 32}, r)
	r, err = ParseResolver(":53")
	require.NoError(t, err)
	require.Equal(t, ":53", r.Addr)
	// DoH keeps the URL as it is written, as Xray does.
	r, err = ParseResolver("https://dns.example:8443/dns-query?x=1")
	require.NoError(t, err)
	require.Equal(t, ResolverConfig{Type: "https", Addr: "https://dns.example:8443/dns-query?x=1", Worker: 32}, r)
	r, err = ParseResolver("https://1.1.1.1/dns-query")
	require.NoError(t, err)
	require.Equal(t, "https://1.1.1.1/dns-query", r.Addr)
	for _, bad := range []string{"", "http://1.1.1.1/dns-query", "https:///dns-query", "https://1.1.1.1:0/x", "quic://1.1.1.1", "1.1.1.1:0", "1.1.1.1:x"} {
		_, err := ParseResolver(bad)
		require.Error(t, err, bad)
	}
}

// Zone names are read as Xray-core reads them since XTLS/Xray-core#7349:
// dots around the name are dropped, an empty label or one over 63 bytes is
// refused when the config is read, not when the first query is packed.
func TestDomainDots(t *testing.T) {
	for _, name := range []string{"t.example.com.", ".t.example.com", "T.Example.Com"} {
		d, err := NewDomain(name, 255, 63, []uint16{TypeTXT}, 0)
		require.NoError(t, err, name)
		require.Equal(t, "t.example.com.", strings.ToLower(d.name.String()), name)
	}
	d, err := NewDomain("тест.рф.", 255, 63, []uint16{TypeTXT}, 0)
	require.NoError(t, err)
	require.Equal(t, "xn--e1aybc.xn--p1ai.", d.name.String())
	for _, bad := range []string{".", "..", "a..b", "a.", strings.Repeat("a", 64) + ".example.com"} {
		if bad == "a." {
			// one label is a name, as in Xray
			_, err := NewDomain(bad, 255, 63, []uint16{TypeTXT}, 0)
			require.NoError(t, err)
			continue
		}
		_, err := NewDomain(bad, 255, 63, []uint16{TypeTXT}, 0)
		require.Error(t, err, bad)
	}
}

func TestResolverOptions(t *testing.T) {
	cfg, err := New(Option{
		Domains: []DomainOption{{Names: []string{"t.example.com"}}},
		Resolvers: []ResolverOption{
			{Addrs: []string{"1.1.1.1", "tcp://8.8.8.8"}, Worker: 3},
			{Addrs: []string{"https://dns.example/dns-query"}},
			{Addrs: []string{"https://dns.example/dns-query"}, TLSConfig: &TLSOption{ALPN: stringList{"h3"}}, QUICConfig: &QUICOption{Congestion: "force-brutal", BrutalUp: "100 mbps"}},
		},
	})
	require.NoError(t, err)
	require.Len(t, cfg.Resolvers, 4)
	require.Equal(t, 3, cfg.Resolvers[0].Worker)
	require.Equal(t, 3, cfg.Resolvers[1].Worker)
	require.Equal(t, 32, cfg.Resolvers[2].Worker)
	require.Nil(t, cfg.Resolvers[2].TLS) // the default TLS: SNI from the URL, a Chrome hello
	require.True(t, cfg.Resolvers[3].TLS.H3())
	require.Equal(t, uint64(100_000_000/8), cfg.Resolvers[3].QUIC.BrutalUp)

	base := func(r ResolverOption) Option {
		return Option{Domains: []DomainOption{{Names: []string{"t.example.com"}}}, Resolvers: []ResolverOption{r}}
	}
	for name, r := range map[string]ResolverOption{
		"negative worker":     {Addrs: []string{"tcp://8.8.8.8"}, Worker: -1},
		"allow insecure":      {Addrs: []string{"https://dns.example/q"}, TLSConfig: &TLSOption{AllowInsecure: true}},
		"bad fingerprint":     {Addrs: []string{"https://dns.example/q"}, TLSConfig: &TLSOption{Fingerprint: "netscape"}},
		"bad pin":             {Addrs: []string{"https://dns.example/q"}, TLSConfig: &TLSOption{PinnedPeerCertSha256: stringList{"abcd"}}},
		"bad ech":             {Addrs: []string{"https://dns.example/q"}, TLSConfig: &TLSOption{ECHConfigList: "https://1.1.1.1/dns-query"}},
		"brutal over h3":      {Addrs: []string{"https://dns.example/q"}, TLSConfig: &TLSOption{ALPN: stringList{"h3"}}, QUICConfig: &QUICOption{Congestion: "brutal"}},
		"force-brutal, no up": {Addrs: []string{"https://dns.example/q"}, QUICConfig: &QUICOption{Congestion: "force-brutal"}},
		"slow brutal":         {Addrs: []string{"https://dns.example/q"}, QUICConfig: &QUICOption{Congestion: "force-brutal", BrutalUp: "500 kbps"}},
		"bad congestion":      {Addrs: []string{"https://dns.example/q"}, QUICConfig: &QUICOption{Congestion: "cubic"}},
		"bad profile":         {Addrs: []string{"https://dns.example/q"}, QUICConfig: &QUICOption{BBRProfile: "turbo"}},
		"small window":        {Addrs: []string{"https://dns.example/q"}, QUICConfig: &QUICOption{MaxStreamReceiveWindow: 1000}},
		"idle timeout":        {Addrs: []string{"https://dns.example/q"}, QUICConfig: &QUICOption{MaxIdleTimeout: 200}},
		"keep alive":          {Addrs: []string{"https://dns.example/q"}, QUICConfig: &QUICOption{KeepAlivePeriod: 1}},
	} {
		_, err := New(base(r))
		require.Error(t, err, name)
	}
	// brutal is fine where the QUIC settings are not used.
	_, err = New(base(ResolverOption{Addrs: []string{"https://dns.example/q"}, QUICConfig: &QUICOption{Congestion: "brutal"}}))
	require.NoError(t, err)
}

func TestTLSOption(t *testing.T) {
	c, err := (&TLSOption{}).Build()
	require.NoError(t, err)
	require.Equal(t, "chrome", c.Fingerprint) // Chrome hello by default, as in Xray
	require.Empty(t, c.NextProtos)
	require.False(t, c.H3())

	c, err = (&TLSOption{Fingerprint: "UNSAFE", ALPN: stringList{"h2, http/1.1"}, PinnedPeerCertSha256: stringList{strings.Repeat("ab", 32) + "," + strings.Repeat("CD:", 31) + "CD"}, VerifyPeerCertByName: stringList{"a.example, b.example"}}).Build()
	require.NoError(t, err)
	require.Equal(t, "", c.Fingerprint)
	require.Equal(t, []string{"h2", "http/1.1"}, c.NextProtos)
	require.Len(t, c.Pins, 2)
	require.Equal(t, []string{"a.example", "b.example"}, c.VerifyNames)

	var l stringList
	require.NoError(t, l.UnmarshalText([]byte(" h3 ")))
	require.Equal(t, stringList{"h3"}, l)
}

func TestParseBandwidth(t *testing.T) {
	for in, want := range map[string]uint64{
		"":          0,
		"8":         1,
		"800 bps":   100,
		"1k":        125,
		"100 mbps":  12_500_000,
		"1.5 Gbps":  187_500_000,
		"2 tb":      250_000_000_000,
		" 64 kbps ": 8000,
	} {
		got, err := ParseBandwidth(in)
		require.NoError(t, err, in)
		require.Equal(t, want, got, in)
	}
	for _, bad := range []string{"fast", "10 mibps", "1.2.3m"} {
		_, err := ParseBandwidth(bad)
		require.Error(t, err, bad)
	}
}

func TestOption(t *testing.T) {
	cfg, err := New(Option{
		Domains:   []DomainOption{{Names: []string{"t.example.com", "x.example.org"}, Types: []int{16, 1}}},
		Resolvers: []ResolverOption{{Addrs: []string{"1.1.1.1", "tcp://8.8.8.8"}}},
		ExtraPoll: 1,
	})
	require.NoError(t, err)
	require.Len(t, cfg.Domains, 2)
	require.Equal(t, 255, cfg.Domains[0].LenLimit)
	require.Equal(t, []uint16{16, 1}, cfg.Domains[0].Types)
	require.Len(t, cfg.Resolvers, 2)
	require.Equal(t, int32(1), cfg.ExtraPoll)

	_, err = New(Option{Resolvers: []ResolverOption{{Addrs: []string{"1.1.1.1"}}}})
	require.Error(t, err)
	_, err = New(Option{Domains: []DomainOption{{Names: []string{"t.example.com"}}}})
	require.Error(t, err)
	_, err = New(Option{Domains: []DomainOption{{Names: []string{"t.example.com"}}}, Resolvers: []ResolverOption{{Addrs: []string{"1.1.1.1"}}}, ExtraPoll: 4})
	require.Error(t, err)
}

// startServer runs an xdns server on loopback, as Xray's inbound would, with
// the client's resolver pointed straight at it.
func startServer(t *testing.T, cfg *Config) (net.PacketConn, string) {
	t.Helper()
	raw, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	server, err := cfg.WrapPacketConnServer(raw)
	require.NoError(t, err)
	t.Cleanup(func() { server.Close() })
	return server, raw.LocalAddr().String()
}

func TestClientServerRoundTrip(t *testing.T) {
	for _, resolverScheme := range []string{"udp://", "tcp://"} {
		for _, types := range [][]int{{16}, {1}, {5}, {28}, {1, 16}} {
			serverCfg, err := New(Option{
				Domains:   []DomainOption{{Names: []string{"t.example.com"}, EDNS0: 4096}},
				Resolvers: []ResolverOption{{Addrs: []string{"127.0.0.1"}}},
			})
			require.NoError(t, err)
			server, serverAddr := startServer(t, serverCfg)
			if resolverScheme == "tcp://" {
				// DNS over TCP: a small relay that frames the UDP server.
				serverAddr = startTCPRelay(t, serverAddr)
			}

			clientCfg, err := New(Option{
				Domains:   []DomainOption{{Names: []string{"t.example.com"}, Types: types, EDNS0: 4096}},
				Resolvers: []ResolverOption{{Addrs: []string{resolverScheme + serverAddr}}},
			})
			require.NoError(t, err)
			dest := finalmask.Destination{Host: "ignored.example", Port: 443}
			client, err := clientCfg.WrapPacketConnClient(context.Background(), nil, &dest, localDialer())
			require.NoError(t, err)

			// A records carry at most 255*3-1 bytes per answer, so the
			// downlink of type A is limited to that; QUIC-sized packets need
			// TXT, CNAME or AAAA answers.
			// A records carry at most 255*3-1 bytes per answer, CNAME and
			// AAAA about 2000 with EDNS0 4096; only TXT holds the 2500.
			sizes := []int{10, 300, 700}
			switch types[0] {
			case 1:
			case 16:
				sizes = append(sizes, 1200, 2500)
			default:
				sizes = append(sizes, 1200)
			}
			for _, size := range sizes {
				up := make([]byte, size)
				_, _ = rand.Read(up)
				_, err = client.WriteTo(up, nil)
				require.NoError(t, err)
				buf := make([]byte, 4096)
				n, from, err := readWithTimeout(server, buf, 5*time.Second)
				require.NoError(t, err, "scheme %s types %v size %d", resolverScheme, types, size)
				require.True(t, bytes.Equal(up, buf[:n]), "scheme %s types %v size %d", resolverScheme, types, size)

				down := make([]byte, size)
				_, _ = rand.Read(down)
				_, err = server.WriteTo(down, from)
				require.NoError(t, err)
				n, _, err = readWithTimeout(client, buf, 5*time.Second)
				require.NoError(t, err, "scheme %s types %v size %d", resolverScheme, types, size)
				require.True(t, bytes.Equal(down, buf[:n]), "scheme %s types %v size %d", resolverScheme, types, size)
			}
			require.NoError(t, client.Close())
			_, _, err = client.ReadFrom(make([]byte, 16))
			require.Error(t, err)
		}
	}
}

func readWithTimeout(conn net.PacketConn, buf []byte, d time.Duration) (int, net.Addr, error) {
	type result struct {
		n    int
		addr net.Addr
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		n, addr, err := conn.ReadFrom(buf)
		ch <- result{n, addr, err}
	}()
	select {
	case r := <-ch:
		return r.n, r.addr, r.err
	case <-time.After(d):
		return 0, nil, context.DeadlineExceeded
	}
}

// startTCPRelay accepts DNS-over-TCP and forwards each message to the UDP
// server, sending the answers back framed.
func startTCPRelay(t *testing.T, udpServer string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				udp, err := net.Dial("udp", udpServer)
				if err != nil {
					return
				}
				defer udp.Close()
				go func() {
					buf := make([]byte, 4096)
					for {
						n, err := udp.Read(buf)
						if err != nil {
							return
						}
						frame := append([]byte{byte(n >> 8), byte(n)}, buf[:n]...)
						if _, err := conn.Write(frame); err != nil {
							return
						}
					}
				}()
				buf := make([]byte, 4096)
				for {
					if _, err := readFull(conn, buf[:2]); err != nil {
						return
					}
					n := int(buf[0])<<8 | int(buf[1])
					if _, err := readFull(conn, buf[:n]); err != nil {
						return
					}
					if _, err := udp.Write(buf[:n]); err != nil {
						return
					}
				}
			}()
		}
	}()
	return ln.Addr().String()
}

func readFull(conn net.Conn, buf []byte) (int, error) {
	read := 0
	for read < len(buf) {
		n, err := conn.Read(buf[read:])
		read += n
		if err != nil {
			return read, err
		}
	}
	return read, nil
}
