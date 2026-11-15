package inbound_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/component/ca"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener/inbound"
	"github.com/metacubex/mihomo/log"

	"github.com/metacubex/http"
	"github.com/metacubex/quic-go"
	"github.com/metacubex/quic-go/http3"
	"github.com/metacubex/quic-go/quicvarint"
	"github.com/metacubex/tls"

	"github.com/stretchr/testify/require"
)

// quicRelay forwards UDP to a QUIC server and counts, per client socket, the
// 0-RTT packets it sends, and keeps the size and the source connection ID
// length of its first datagram. Long header lengths are in the clear.
type quicRelay struct {
	front  *net.UDPConn
	server *net.UDPAddr

	mu      sync.Mutex
	clients map[string]*quicRelayClient
	order   []*quicRelayClient
}

type quicRelayClient struct {
	addr           *net.UDPAddr
	upstream       *net.UDPConn
	zeroRTTPackets int
	zeroRTTBytes   int
	first          quicInitial
}

// quicInitial is the first datagram of a QUIC connection.
type quicInitial struct {
	size, scidLen int
}

func newQUICRelay(t *testing.T, server string) *quicRelay {
	t.Helper()
	addr, err := net.ResolveUDPAddr("udp", server)
	require.NoError(t, err)
	front, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	r := &quicRelay{front: front, server: addr, clients: map[string]*quicRelayClient{}}
	go r.serve()
	t.Cleanup(func() {
		_ = front.Close()
		r.mu.Lock()
		defer r.mu.Unlock()
		for _, c := range r.clients {
			_ = c.upstream.Close()
		}
	})
	return r
}

func (r *quicRelay) port() int { return r.front.LocalAddr().(*net.UDPAddr).Port }

func (r *quicRelay) serve() {
	b := make([]byte, 65536)
	for {
		n, from, err := r.front.ReadFromUDP(b)
		if err != nil {
			return
		}
		r.mu.Lock()
		c := r.clients[from.String()]
		if c == nil {
			up, err := net.DialUDP("udp", nil, r.server)
			if err != nil {
				r.mu.Unlock()
				return
			}
			c = &quicRelayClient{addr: from, upstream: up, first: quicInitial{size: n, scidLen: -1}}
			if n > 6 && 6+int(b[5]) < n {
				c.first.scidLen = int(b[6+int(b[5])])
			}
			r.clients[from.String()] = c
			r.order = append(r.order, c)
			go func() {
				b := make([]byte, 65536)
				for {
					n, err := up.Read(b)
					if err != nil {
						return
					}
					_, _ = r.front.WriteToUDP(b[:n], from)
				}
			}()
		}
		packets, size := zeroRTTPackets(b[:n])
		c.zeroRTTPackets += packets
		c.zeroRTTBytes += size
		up := c.upstream
		r.mu.Unlock()
		_, _ = up.Write(b[:n])
	}
}

// initials returns the first datagram of each client socket, in the order
// they appeared: one per QUIC connection.
func (r *quicRelay) initials() []quicInitial {
	r.mu.Lock()
	defer r.mu.Unlock()
	var initials []quicInitial
	for _, c := range r.order {
		initials = append(initials, c.first)
	}
	return initials
}

// quicProfileWire is what a relay sees of each QUIC handshake profile of
// quicProfileCases, resumed or not.
type quicProfileWire struct {
	// first is the first datagram: its size, and the length of the source
	// connection ID but for off, quic-go's own.
	first quicInitial
	// zeroRTTPackets is the range of 0-RTT packets of a resumed connection
	// that only sends the HTTP/3 SETTINGS early. A client with a non-empty
	// source connection ID (quic-go's own, Firefox's 3 bytes) also issues the
	// server's NEW_CONNECTION_ID frames in 0-RTT, from the limit the ticket
	// restores; whether they share a packet with the SETTINGS depends on
	// timing (one packet on macOS, often two on Linux CI).
	zeroRTTPackets [2]int
}

var quicProfileWires = map[string]quicProfileWire{
	"off":     {first: quicInitial{size: 1280, scidLen: -1}, zeroRTTPackets: [2]int{1, 2}},
	"chrome":  {first: quicInitial{size: 1250, scidLen: 0}, zeroRTTPackets: [2]int{1, 1}},
	"firefox": {first: quicInitial{size: 1252, scidLen: 3}, zeroRTTPackets: [2]int{1, 2}},
	"safari":  {first: quicInitial{size: 1200, scidLen: 0}, zeroRTTPackets: [2]int{1, 1}},
}

// checkQUICProfileInitials checks that every connection the relay saw was made
// with the handshake profile tc.
func checkQUICProfileInitials(t *testing.T, relay *quicRelay, tc quicProfileCase) {
	t.Helper()
	wire, ok := quicProfileWires[tc.name]
	require.True(t, ok, tc.name)
	initials := relay.initials()
	require.NotEmpty(t, initials)
	for i, got := range initials {
		require.Equal(t, wire.first.size, got.size, "first datagram of connection %d", i)
		if wire.first.scidLen >= 0 {
			require.Equal(t, wire.first.scidLen, got.scidLen, "source connection ID of connection %d", i)
		}
	}
}

// connections returns the 0-RTT packets and bytes of each client socket, in
// the order they appeared: one per QUIC connection.
func (r *quicRelay) connections() (packets, bytes []int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, c := range r.order {
		packets = append(packets, c.zeroRTTPackets)
		bytes = append(bytes, c.zeroRTTBytes)
	}
	return packets, bytes
}

// zeroRTTPackets counts the 0-RTT packets of a datagram, coalesced or not.
func zeroRTTPackets(d []byte) (packets, size int) {
	for len(d) > 7 && d[0]&0x80 != 0 {
		typ := (d[0] >> 4) & 3
		p := 6 + int(d[5])
		if p >= len(d) {
			return
		}
		p += 1 + int(d[p])
		if typ == 0 { // Initial: token
			l, n, err := quicvarint.Parse(d[p:])
			if err != nil {
				return
			}
			p += n + int(l)
		}
		if p > len(d) {
			return
		}
		l, n, err := quicvarint.Parse(d[p:])
		if err != nil {
			return
		}
		p += n + int(l)
		if p > len(d) {
			p = len(d)
		}
		if typ == 1 {
			packets++
			size += p
		}
		d = d[p:]
	}
	return
}

// quicResumptionLog collects the "[QUIC] proxy: TLS session resumed" lines.
type quicResumptionLog struct {
	mu    sync.Mutex
	lines []string
}

func watchQUICResumption(t *testing.T, proxy string) *quicResumptionLog {
	t.Helper()
	l := &quicResumptionLog{}
	sub := log.Subscribe()
	t.Cleanup(func() { log.UnSubscribe(sub) })
	prefix := "[QUIC] " + proxy + ": "
	go func() {
		for ev := range sub {
			if strings.HasPrefix(ev.Payload, prefix) {
				l.mu.Lock()
				l.lines = append(l.lines, strings.TrimPrefix(ev.Payload, prefix))
				l.mu.Unlock()
			}
		}
	}()
	return l
}

// wait returns the first n lines.
func (l *quicResumptionLog) wait(t *testing.T, n int) []string {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		l.mu.Lock()
		if len(l.lines) >= n {
			lines := append([]string(nil), l.lines[:n]...)
			l.mu.Unlock()
			return lines
		}
		l.mu.Unlock()
		time.Sleep(20 * time.Millisecond)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	t.Fatalf("got %d QUIC handshake log lines, want %d: %q", len(l.lines), n, l.lines)
	return nil
}

func resumptionLine(resumed, zeroRTT bool) string {
	return fmt.Sprintf("TLS session resumed: %t, 0-RTT accepted: %t", resumed, zeroRTT)
}

// A password longer than any 0-RTT packet: if the auth request went out in
// 0-RTT, the 0-RTT bytes would show it.
var longHysteria2Password = strings.Repeat("p", 1500)

// TestInboundHysteria2_SessionResumption: our listener issues tickets without
// 0-RTT, so the second connection resumes in 1-RTT, with each browser's
// handshake and with disable-chrome-parrot.
func TestInboundHysteria2_SessionResumption(t *testing.T) {
	for _, tc := range quicProfileCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			inboundOptions := inbound.Hysteria2Option{
				BaseOption:  inbound.BaseOption{NameStr: "hysteria2_inbound", Listen: "127.0.0.1", Port: "0"},
				Users:       map[string]string{"test": longHysteria2Password},
				Certificate: tlsCertificate,
				PrivateKey:  tlsPrivateKey,
			}
			in, err := inbound.NewHysteria2(&inboundOptions)
			require.NoError(t, err)
			tunnel := NewHttpTestTunnel()
			t.Cleanup(func() { _ = tunnel.Close() })
			tunnel.HandleUDPPacketFn = func(packet C.UDPPacket, metadata *C.Metadata) {
				data := append([]byte(nil), packet.Data()...)
				_, _ = packet.WriteBack(data, metadata.UDPAddr())
				packet.Drop()
			}
			require.NoError(t, in.Listen(tunnel))
			t.Cleanup(func() { _ = in.Close() })

			relay := newQUICRelay(t, in.Address())
			name := "hysteria2_resumption_" + tc.name
			logs := watchQUICResumption(t, name)
			option := outbound.Hysteria2Option{
				Name:                    name,
				Server:                  "127.0.0.1",
				Port:                    relay.port(),
				Password:                longHysteria2Password,
				Fingerprint:             tlsFingerprint,
				DisableChromeParrot:     tc.disable,
				ClientFingerprint:       tc.fingerprint,
				EnableSessionResumption: true,
			}
			option.DialerForAPI = tunnel.NewDialer()
			option.TunnelForAPI = tunnel
			out, err := outbound.NewHysteria2(option)
			require.NoError(t, err)
			t.Cleanup(func() { _ = out.Close() })

			for i := 0; i < 3; i++ {
				udpEcho(t, out, []int{1, 1300})
				tunnel.DoSequentialTest(t, out)
				// Waits for the ticket the server sent, then for a new connection.
				time.Sleep(200 * time.Millisecond)
				out.CloseIdle(0)
			}
			require.Equal(t, []string{
				resumptionLine(false, false),
				resumptionLine(true, false),
				resumptionLine(true, false),
			}, logs.wait(t, 3))
			packets, _ := relay.connections()
			require.Equal(t, []int{0, 0, 0}, packets, "no 0-RTT ticket, no 0-RTT")
			checkQUICProfileInitials(t, relay, tc)
		})
	}
}

// fakeHysteria2Server is a Hysteria2 auth endpoint over HTTP/3 that takes
// 0-RTT, which our listener does not; it records how each auth request came.
type fakeHysteria2Server struct {
	mu    sync.Mutex
	auths []fakeHysteria2Auth
	conns []quic.ConnectionState
}

type fakeHysteria2Auth struct {
	handshakeComplete, didResume, authOK bool
}

func startFakeHysteria2Server(t *testing.T, password string) (*fakeHysteria2Server, string) {
	t.Helper()
	cert, err := tls.X509KeyPair([]byte(tlsCertificate), []byte(tlsPrivateKey))
	require.NoError(t, err)
	tlsConf := http3.ConfigureTLSConfig(&tls.Config{Certificates: []tls.Certificate{cert}})
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	ln, err := quic.ListenEarly(pc, tlsConf, &quic.Config{Allow0RTT: true, EnableDatagrams: true})
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close(); _ = pc.Close() })

	s := &fakeHysteria2Server{}
	srv := &http3.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.auths = append(s.auths, fakeHysteria2Auth{
			handshakeComplete: r.TLS.HandshakeComplete,
			didResume:         r.TLS.DidResume,
			authOK:            r.Method == http.MethodPost && r.URL.Path == "/auth" && r.Header.Get("Hysteria-Auth") == password,
		})
		s.mu.Unlock()
		w.Header().Set("Hysteria-UDP", "false")
		w.Header().Set("Hysteria-CC-RX", "auto")
		w.WriteHeader(233)
	})}
	go func() {
		for {
			conn, err := ln.Accept(context.Background())
			if err != nil {
				return
			}
			go srv.ServeQUICConn(conn)
			go func() {
				select {
				case <-conn.HandshakeComplete():
				case <-conn.Context().Done():
					return
				}
				s.mu.Lock()
				s.conns = append(s.conns, conn.ConnectionState())
				s.mu.Unlock()
			}()
		}
	}()
	return s, pc.LocalAddr().String()
}

// TestHysteria2SessionResumption0RTT: against a server that takes 0-RTT, the
// resumed connection sends only the HTTP/3 SETTINGS in 0-RTT: the auth
// request waits for the handshake.
func TestHysteria2SessionResumption0RTT(t *testing.T) {
	for _, tc := range quicProfileCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			server, addr := startFakeHysteria2Server(t, longHysteria2Password)
			relay := newQUICRelay(t, addr)
			name := "hysteria2_0rtt_" + tc.name
			logs := watchQUICResumption(t, name)
			out, err := outbound.NewHysteria2(outbound.Hysteria2Option{
				Name:                    name,
				Server:                  "127.0.0.1",
				Port:                    relay.port(),
				Password:                longHysteria2Password,
				Fingerprint:             tlsFingerprint,
				DisableChromeParrot:     tc.disable,
				ClientFingerprint:       tc.fingerprint,
				EnableSessionResumption: true,
			})
			require.NoError(t, err)
			t.Cleanup(func() { _ = out.Close() })

			dst := netip.MustParseAddrPort("127.0.0.1:9")
			for i := 0; i < 3; i++ {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				conn, err := out.DialContext(ctx, &C.Metadata{NetWork: C.TCP, DstIP: dst.Addr(), DstPort: dst.Port()})
				cancel()
				require.NoError(t, err) // the auth went through
				_ = conn.Close()
				time.Sleep(200 * time.Millisecond)
				out.CloseIdle(0)
			}
			require.Equal(t, []string{
				resumptionLine(false, false),
				resumptionLine(true, true),
				resumptionLine(true, true),
			}, logs.wait(t, 3))

			server.mu.Lock()
			auths := append([]fakeHysteria2Auth(nil), server.auths...)
			conns := append([]quic.ConnectionState(nil), server.conns...)
			server.mu.Unlock()
			require.Len(t, auths, 3)
			for i, a := range auths {
				require.True(t, a.authOK, "auth %d", i)
				require.True(t, a.handshakeComplete, "auth %d came in 0-RTT", i)
				require.Equal(t, i > 0, a.didResume, "auth %d", i)
			}
			require.Len(t, conns, 3)
			require.False(t, conns[0].Used0RTT)
			require.True(t, conns[1].Used0RTT)
			require.True(t, conns[2].Used0RTT)

			packets, sizes := relay.connections()
			require.Len(t, packets, 3)
			require.Zero(t, packets[0])
			for i := 1; i < 3; i++ {
				// The control stream with the SETTINGS.
				want := quicProfileWires[tc.name].zeroRTTPackets
				require.GreaterOrEqual(t, packets[i], want[0], "0-RTT packets of connection %d", i)
				require.LessOrEqual(t, packets[i], want[1], "0-RTT packets of connection %d", i)
				require.Less(t, sizes[i], 200, "0-RTT bytes of connection %d", i)
			}
			t.Logf("0-RTT bytes per connection: %v", sizes)
			checkQUICProfileInitials(t, relay, tc)
		})
	}
}

// TestHysteria2XrayServerSessionResumption: against Xray's hysteria inbound
// the second connection resumes.
//
//	XRAY_BIN=/path/to/xray go test ./listener/inbound/ -run TestHysteria2XrayServerSessionResumption -v
func TestHysteria2XrayServerSessionResumption(t *testing.T) {
	xrayBinary := os.Getenv("XRAY_BINARY")
	if xrayBinary == "" {
		xrayBinary = os.Getenv("XRAY_BIN")
	}
	if xrayBinary == "" {
		t.Skip("XRAY_BINARY is not set; point it at an Xray-core executable")
	}
	tcpEcho := startVMessInteropEcho(t)
	certPEM, keyPEM, fingerprint, err := ca.NewRandomTLSKeyPair(ca.KeyPairTypeP256)
	require.NoError(t, err)
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	require.NoError(t, os.WriteFile(certFile, []byte(certPEM), 0o600))
	require.NoError(t, os.WriteFile(keyFile, []byte(keyPEM), 0o600))

	hyPort := reserveUDPPort(t)
	readyPort := vmessInteropReserveTCPPort(t)
	config, err := json.Marshal(map[string]any{
		"log": map[string]any{"loglevel": "warning"},
		"inbounds": []any{
			map[string]any{
				"listen": "127.0.0.1", "port": hyPort, "protocol": "hysteria",
				"settings": map[string]any{"version": 2, "clients": []any{map[string]any{"auth": longHysteria2Password, "email": "a@test"}}},
				"streamSettings": map[string]any{
					"network":          "hysteria",
					"hysteriaSettings": map[string]any{"version": 2},
					"security":         "tls",
					"tlsSettings": map[string]any{
						"alpn":         []string{"h3"},
						"certificates": []any{map[string]any{"certificateFile": certFile, "keyFile": keyFile}},
						// Xray sends no session tickets without it.
						"enableSessionResumption": true,
					},
				},
			},
			map[string]any{
				"listen": "127.0.0.1", "port": readyPort.Port(), "protocol": "dokodemo-door",
				"settings": map[string]any{"address": "127.0.0.1", "port": 9, "network": "tcp"},
			},
		},
		"outbounds": []any{map[string]any{
			"protocol": "freedom",
			"settings": map[string]any{"finalRules": []any{map[string]any{"action": "allow", "ip": []string{"127.0.0.1/32"}}}},
		}},
	})
	require.NoError(t, err)
	startXrayRealityServer(t, xrayBinary, config, readyPort)

	for _, tc := range quicProfileCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			relay := newQUICRelay(t, fmt.Sprintf("127.0.0.1:%d", hyPort))
			name := "hysteria2_xray_resumption_" + tc.name
			logs := watchQUICResumption(t, name)
			out, err := outbound.NewHysteria2(outbound.Hysteria2Option{
				Name:                    name,
				Server:                  "127.0.0.1",
				Port:                    relay.port(),
				Password:                longHysteria2Password,
				Fingerprint:             fingerprint,
				DisableChromeParrot:     tc.disable,
				ClientFingerprint:       tc.fingerprint,
				EnableSessionResumption: true,
			})
			require.NoError(t, err)
			t.Cleanup(func() { _ = out.Close() })

			echoAddr := netip.MustParseAddrPort(tcpEcho)
			for i := 0; i < 3; i++ {
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
				conn, err := out.DialContext(ctx, &C.Metadata{NetWork: C.TCP, DstIP: echoAddr.Addr(), DstPort: echoAddr.Port()})
				require.NoError(t, err)
				msg := []byte(fmt.Sprintf("hello %d", i))
				_, err = conn.Write(msg)
				require.NoError(t, err)
				got := make([]byte, len(msg))
				_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
				_, err = io.ReadFull(conn, got)
				require.NoError(t, err)
				require.Equal(t, msg, got)
				_ = conn.Close()
				cancel()
				time.Sleep(200 * time.Millisecond)
				out.CloseIdle(0)
			}
			lines := logs.wait(t, 3)
			packets, sizes := relay.connections()
			t.Logf("handshakes: %q; 0-RTT packets %v, bytes %v", lines, packets, sizes)
			require.Equal(t, resumptionLine(false, false), lines[0])
			for i := 1; i < 3; i++ {
				require.True(t, strings.HasPrefix(lines[i], "TLS session resumed: true"), lines[i])
				require.Less(t, sizes[i], 200, "only the SETTINGS in 0-RTT")
			}
			checkQUICProfileInitials(t, relay, tc)
		})
	}
}
