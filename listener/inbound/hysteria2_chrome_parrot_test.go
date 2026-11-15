package inbound_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener/inbound"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The hysteria2 tests run with the default, Chrome's QUIC handshake; these run
// quic-go's own, with disable-chrome-parrot.
func TestInboundHysteria2_NoChromeParrot(t *testing.T) {
	inboundOptions := inbound.Hysteria2Option{
		Certificate: tlsCertificate,
		PrivateKey:  tlsPrivateKey,
	}
	outboundOptions := outbound.Hysteria2Option{
		Fingerprint:         tlsFingerprint,
		DisableChromeParrot: true,
	}
	testInboundHysteria2TLS(t, inboundOptions, outboundOptions)
}

func TestInboundHysteria2_NoChromeParrotSalamander(t *testing.T) {
	inboundOptions := inbound.Hysteria2Option{
		Certificate:  tlsCertificate,
		PrivateKey:   tlsPrivateKey,
		Obfs:         "salamander",
		ObfsPassword: userUUID,
	}
	outboundOptions := outbound.Hysteria2Option{
		Fingerprint:         tlsFingerprint,
		Obfs:                "salamander",
		ObfsPassword:        userUUID,
		DisableChromeParrot: true,
	}
	testInboundHysteria2TLS(t, inboundOptions, outboundOptions)
}

func TestInboundHysteria2_NoChromeParrotGecko(t *testing.T) {
	inboundOptions := inbound.Hysteria2Option{
		Certificate:  tlsCertificate,
		PrivateKey:   tlsPrivateKey,
		Obfs:         "gecko",
		ObfsPassword: userUUID,
	}
	outboundOptions := outbound.Hysteria2Option{
		Fingerprint:         tlsFingerprint,
		Obfs:                "gecko",
		ObfsPassword:        userUUID,
		DisableChromeParrot: true,
	}
	testInboundHysteria2TLS(t, inboundOptions, outboundOptions)
}

// udpForwarder stands between the client and a hysteria2 listener the way a
// port-hopping server's DNAT rule does: datagrams to any of its ports reach
// the one listener from one source per client, and the replies leave from
// the port the client sent to last. It also records the plaintext part of the
// client's Initial packets.
type udpForwarder struct {
	t      *testing.T
	server *net.UDPAddr
	fronts []*net.UDPConn

	mu       sync.Mutex
	clients  map[string]*forwardedClient
	perFront map[int]int // datagrams from clients per front port
	initials []initialHeader
}

type forwardedClient struct {
	addr     *net.UDPAddr
	upstream *net.UDPConn
	front    *net.UDPConn
}

type initialHeader struct {
	size    int
	dcidLen int
	scidLen int
}

func newUDPForwarder(t *testing.T, server string, ports int) *udpForwarder {
	addr, err := net.ResolveUDPAddr("udp", server)
	require.NoError(t, err)
	f := &udpForwarder{t: t, server: addr, clients: map[string]*forwardedClient{}, perFront: map[int]int{}}
	for i := 0; i < ports; i++ {
		c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		require.NoError(t, err)
		f.fronts = append(f.fronts, c)
		go f.serveFront(c)
	}
	t.Cleanup(f.close)
	return f
}

func (f *udpForwarder) close() {
	for _, c := range f.fronts {
		_ = c.Close()
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.clients {
		_ = c.upstream.Close()
	}
}

func (f *udpForwarder) ports() []int {
	var out []int
	for _, c := range f.fronts {
		out = append(out, c.LocalAddr().(*net.UDPAddr).Port)
	}
	return out
}

func (f *udpForwarder) serveFront(front *net.UDPConn) {
	b := make([]byte, 65536)
	port := front.LocalAddr().(*net.UDPAddr).Port
	for {
		n, from, err := front.ReadFromUDP(b)
		if err != nil {
			return
		}
		f.mu.Lock()
		f.perFront[port]++
		// A long header Initial: its size and connection ID lengths are in
		// the clear.
		if n > 7 && b[0]&0x80 != 0 && b[0]&0x30 == 0 {
			dcid := int(b[5])
			if 6+dcid < n {
				f.initials = append(f.initials, initialHeader{size: n, dcidLen: dcid, scidLen: int(b[6+dcid])})
			}
		}
		c := f.clients[from.String()]
		if c == nil {
			up, err := net.DialUDP("udp", nil, f.server)
			if err != nil {
				f.mu.Unlock()
				return
			}
			c = &forwardedClient{addr: from, upstream: up}
			f.clients[from.String()] = c
			go f.serveUpstream(c)
		}
		c.front = front
		up := c.upstream
		f.mu.Unlock()
		_, _ = up.Write(b[:n])
	}
}

func (f *udpForwarder) serveUpstream(c *forwardedClient) {
	b := make([]byte, 65536)
	for {
		n, err := c.upstream.Read(b)
		if err != nil {
			return
		}
		f.mu.Lock()
		front := c.front
		f.mu.Unlock()
		_, _ = front.WriteToUDP(b[:n], c.addr)
	}
}

func (f *udpForwarder) stats() (clients int, frontsUsed int, initials []initialHeader) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, n := range f.perFront {
		if n > 0 {
			frontsUsed++
		}
	}
	return len(f.clients), frontsUsed, append([]initialHeader(nil), f.initials...)
}

// newHysteria2UDPEchoPair starts a hysteria2 listener whose tunnel echoes UDP
// back to the sender and serves the HTTP test endpoints over TCP, and an
// outbound dialing it through a udpForwarder with the given number of ports.
func newHysteria2UDPEchoPair(t *testing.T, inboundOptions inbound.Hysteria2Option, outboundOptions outbound.Hysteria2Option, ports int) (*TestTunnel, *outbound.Hysteria2, *udpForwarder) {
	inboundOptions.BaseOption = inbound.BaseOption{
		NameStr: "hysteria2_inbound",
		Listen:  "127.0.0.1",
		Port:    "0",
	}
	inboundOptions.Users = map[string]string{"test": userUUID}
	inboundOptions.Certificate = tlsCertificate
	inboundOptions.PrivateKey = tlsPrivateKey
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

	fwd := newUDPForwarder(t, in.Address(), ports)
	frontPorts := fwd.ports()
	outboundOptions.Name = "hysteria2_outbound"
	outboundOptions.Server = "127.0.0.1"
	outboundOptions.Port = frontPorts[0]
	if ports > 1 {
		var list []string
		for _, p := range frontPorts {
			list = append(list, strconv.Itoa(p))
		}
		outboundOptions.Ports = strings.Join(list, ",")
	}
	outboundOptions.Password = userUUID
	outboundOptions.Fingerprint = tlsFingerprint
	outboundOptions.DialerForAPI = tunnel.NewDialer()
	outboundOptions.TunnelForAPI = tunnel
	out, err := outbound.NewHysteria2(outboundOptions)
	require.NoError(t, err)
	t.Cleanup(func() { _ = out.Close() })
	return tunnel, out, fwd
}

// udpEcho sends payloads of the given sizes through the proxy and requires
// each to come back unchanged.
func udpEcho(t *testing.T, out *outbound.Hysteria2, sizes []int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	dst := netip.AddrPortFrom(remoteAddr, 5353)
	pc, err := out.ListenPacketContext(ctx, &C.Metadata{NetWork: C.UDP, DstIP: dst.Addr(), DstPort: dst.Port()})
	require.NoError(t, err)
	defer pc.Close()

	buf := make([]byte, 65536)
	for _, size := range sizes {
		payload := make([]byte, size)
		_, _ = rand.Read(payload)
		var got []byte
		// UDP may lose a datagram; a few attempts per size.
		for attempt := 0; attempt < 5 && got == nil; attempt++ {
			_, err := pc.WriteTo(payload, net.UDPAddrFromAddrPort(dst))
			require.NoError(t, err)
			_ = pc.SetReadDeadline(time.Now().Add(2 * time.Second))
			n, _, err := pc.ReadFrom(buf)
			if err != nil {
				continue
			}
			got = append([]byte(nil), buf[:n]...)
		}
		require.NotNil(t, got, "no echo of %d bytes", size)
		require.True(t, bytes.Equal(payload, got), "echo of %d bytes came back as %d bytes", size, len(got))
	}
}

// Sizes around the client's 1197-byte udp-mtu, above what fits in one
// 1250-byte packet, and the 4096-byte maximum of a hysteria2 UDP message.
var hysteria2UDPSizes = []int{1, 512, 1150, 1197, 1198, 1300, 1450, 2500, 4096}

func TestInboundHysteria2_ChromeParrotUDP(t *testing.T) {
	for _, parrot := range []bool{false, true} {
		for _, obfs := range []string{"", "salamander"} {
			// The listener's udp-mtu 1400 sends datagrams over 1200 bytes
			// to the client: the pitfall of a 1200-byte receive buffer.
			for _, serverMTU := range []int{0, 1400} {
				parrot, obfs, serverMTU := parrot, obfs, serverMTU
				t.Run(fmt.Sprintf("parrot=%v/obfs=%s/server-mtu=%d", parrot, obfs, serverMTU), func(t *testing.T) {
					t.Parallel()
					in := inbound.Hysteria2Option{UdpMTU: serverMTU}
					out := outbound.Hysteria2Option{DisableChromeParrot: !parrot}
					if obfs != "" {
						in.Obfs, in.ObfsPassword = obfs, userUUID
						out.Obfs, out.ObfsPassword = obfs, userUUID
					}
					tunnel, proxy, fwd := newHysteria2UDPEchoPair(t, in, out, 1)
					udpEcho(t, proxy, hysteria2UDPSizes)
					tunnel.DoSequentialTest(t, proxy)

					if obfs != "" {
						return // the headers are obfuscated
					}
					_, _, initials := fwd.stats()
					require.NotEmpty(t, initials)
					if parrot {
						// Later Initials carry the server's connection ID.
						assert.Equal(t, 8, initials[0].dcidLen)
					}
					for _, h := range initials {
						assert.Zero(t, h.scidLen, "source connection ID")
						if parrot {
							assert.Equal(t, 1250, h.size)
						} else {
							assert.Equal(t, 1280, h.size)
						}
					}
				})
			}
		}
	}
}

// The outbound's first Initial goes out at Chrome's size for the address
// family by default (DialQuic hands quic-go the server's *net.UDPAddr), at
// quic-go's own with disable-chrome-parrot.
func TestHysteria2ChromeParrotInitialSize(t *testing.T) {
	for _, tc := range []struct {
		ip     string
		parrot bool
		size   int
	}{
		{"127.0.0.1", true, 1250},
		{"::1", true, 1230},
		{"127.0.0.1", false, 1280},
		{"::1", false, 1280},
	} {
		tc := tc
		t.Run(fmt.Sprintf("%s/parrot=%v", tc.ip, tc.parrot), func(t *testing.T) {
			capture, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(tc.ip)})
			if err != nil {
				t.Skipf("no UDP on %s: %s", tc.ip, err)
			}
			defer capture.Close()
			if strings.Contains(tc.ip, ":") {
				// The resolver refuses IPv6 unless the config enables it.
				disabled := resolver.DisableIPv6
				resolver.DisableIPv6 = false
				defer func() { resolver.DisableIPv6 = disabled }()
			}
			out, err := outbound.NewHysteria2(outbound.Hysteria2Option{
				Name:                "hysteria2_capture",
				Server:              tc.ip,
				Port:                capture.LocalAddr().(*net.UDPAddr).Port,
				Password:            userUUID,
				Fingerprint:         tlsFingerprint,
				DisableChromeParrot: !tc.parrot,
			})
			require.NoError(t, err)
			defer out.Close()

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			go func() {
				_, _ = out.DialContext(ctx, &C.Metadata{NetWork: C.TCP, DstIP: remoteAddr, DstPort: 80})
			}()
			b := make([]byte, 65536)
			require.NoError(t, capture.SetReadDeadline(time.Now().Add(5*time.Second)))
			n, _, err := capture.ReadFromUDP(b)
			require.NoError(t, err)
			require.True(t, n > 7 && b[0]&0x80 != 0 && b[0]&0x30 == 0, "a long header Initial")
			assert.Equal(t, tc.size, n)
			dcid := int(b[5])
			assert.Zero(t, b[6+dcid], "source connection ID")
		})
	}
}

// The session survives port hopping: the ports change under one QUIC
// connection, and a session closed as idle reconnects through the same
// dialer, with Chrome's Initial again.
func TestInboundHysteria2_ChromeParrotPortHopping(t *testing.T) {
	if testing.Short() {
		t.Skip("waits for hops")
	}
	for _, parrot := range []bool{false, true} {
		parrot := parrot
		t.Run(fmt.Sprintf("parrot=%v", parrot), func(t *testing.T) {
			t.Parallel()
			tunnel, proxy, fwd := newHysteria2UDPEchoPair(t, inbound.Hysteria2Option{},
				outbound.Hysteria2Option{DisableChromeParrot: !parrot, HopInterval: "5"}, 4)

			deadline := time.Now().Add(16 * time.Second)
			for time.Now().Before(deadline) {
				tunnel.DoSequentialTest(t, proxy)
				udpEcho(t, proxy, []int{64, 1300})
				time.Sleep(500 * time.Millisecond)
			}
			clients, frontsUsed, initials := fwd.stats()
			assert.Equal(t, 1, clients, "one QUIC connection, from one socket")
			assert.GreaterOrEqual(t, frontsUsed, 2, "hops reached other ports")

			// Close the session as idle; the next request dials again.
			proxy.CloseIdle(0)
			tunnel.DoSequentialTest(t, proxy)
			udpEcho(t, proxy, []int{64, 1300})
			clients, _, initials2 := fwd.stats()
			assert.Equal(t, 2, clients, "a new connection after CloseIdle")
			require.Greater(t, len(initials2), len(initials))
			for _, h := range initials2 {
				assert.Zero(t, h.scidLen)
				if parrot {
					assert.Equal(t, 1250, h.size)
				}
			}
		})
	}
}
