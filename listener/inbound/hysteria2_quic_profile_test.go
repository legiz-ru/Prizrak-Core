package inbound_test

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener/inbound"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The browser of the QUIC handshake comes from client-fingerprint.

// quicProfileCase is a QUIC handshake profile of the interop tests: the
// browser of a client-fingerprint, or off with disable-chrome-parrot.
type quicProfileCase struct {
	name        string
	disable     bool
	fingerprint string
}

var quicProfileCases = []quicProfileCase{
	{"off", true, ""},
	{"chrome", false, ""},
	{"firefox", false, "firefox"},
}

func TestInboundHysteria2_FirefoxParrot(t *testing.T) {
	inboundOptions := inbound.Hysteria2Option{
		Certificate: tlsCertificate,
		PrivateKey:  tlsPrivateKey,
	}
	outboundOptions := outbound.Hysteria2Option{
		Fingerprint:       tlsFingerprint,
		ClientFingerprint: "firefox",
	}
	testInboundHysteria2TLS(t, inboundOptions, outboundOptions)
}

func TestInboundHysteria2_FirefoxParrotSalamander(t *testing.T) {
	inboundOptions := inbound.Hysteria2Option{
		Certificate:  tlsCertificate,
		PrivateKey:   tlsPrivateKey,
		Obfs:         "salamander",
		ObfsPassword: userUUID,
	}
	outboundOptions := outbound.Hysteria2Option{
		Fingerprint:       tlsFingerprint,
		Obfs:              "salamander",
		ObfsPassword:      userUUID,
		ClientFingerprint: "firefox",
	}
	testInboundHysteria2TLS(t, inboundOptions, outboundOptions)
}

// UDP both ways through the Firefox profile, and its Initials on the wire:
// each datagram 1252 bytes (zero-padded after the packet), a 3-byte source
// connection ID, an 8 to 20-byte first destination one.
func TestInboundHysteria2_FirefoxParrotUDP(t *testing.T) {
	for _, serverMTU := range []int{0, 1400} {
		serverMTU := serverMTU
		t.Run(fmt.Sprintf("server-mtu=%d", serverMTU), func(t *testing.T) {
			t.Parallel()
			tunnel, proxy, fwd := newHysteria2UDPEchoPair(t, inbound.Hysteria2Option{UdpMTU: serverMTU},
				outbound.Hysteria2Option{ClientFingerprint: "firefox"}, 1)
			udpEcho(t, proxy, hysteria2UDPSizes)
			tunnel.DoSequentialTest(t, proxy)

			_, _, initials := fwd.stats()
			require.NotEmpty(t, initials)
			assert.GreaterOrEqual(t, initials[0].dcidLen, 8)
			assert.LessOrEqual(t, initials[0].dcidLen, 20)
			for _, h := range initials {
				assert.Equal(t, 3, h.scidLen, "source connection ID")
				assert.Equal(t, 1252, h.size)
			}
		})
	}
}

// The Initial size follows the address family, as for Chrome, and so do the
// connection IDs of each profile; a fingerprint other than Firefox's is
// Chrome, ios and random among them.
func TestHysteria2QUICProfileInitial(t *testing.T) {
	for _, tc := range []struct {
		ip          string
		fingerprint string
		size        int
		scid        int
	}{
		{"127.0.0.1", "firefox", 1252, 3},
		{"::1", "firefox", 1232, 3},
		{"127.0.0.1", "FireFox", 1252, 3},
		{"127.0.0.1", "hellofirefox_auto", 1252, 3},
		{"127.0.0.1", "chrome", 1250, 0},
		{"127.0.0.1", "", 1250, 0},
		{"127.0.0.1", "edge", 1250, 0},
		{"127.0.0.1", "ios", 1250, 0},
		{"127.0.0.1", "random", 1250, 0},
		{"127.0.0.1", "firefox120", 1250, 0},
	} {
		tc := tc
		t.Run(fmt.Sprintf("%s/%s", tc.ip, tc.fingerprint), func(t *testing.T) {
			size, scid := captureHysteria2Initial(t, tc.ip, outbound.Hysteria2Option{ClientFingerprint: tc.fingerprint})
			assert.Equal(t, tc.size, size)
			assert.Equal(t, tc.scid, scid, "source connection ID")
		})
	}
	// With disable-chrome-parrot the fingerprint does nothing.
	size, _ := captureHysteria2Initial(t, "127.0.0.1", outbound.Hysteria2Option{ClientFingerprint: "firefox", DisableChromeParrot: true})
	assert.Equal(t, 1280, size)
}

// captureHysteria2Initial dials a socket on ip that never answers and returns
// the size and the source connection ID length of the first Initial.
func captureHysteria2Initial(t *testing.T, ip string, option outbound.Hysteria2Option) (size, scidLen int) {
	t.Helper()
	capture, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(ip)})
	if err != nil {
		t.Skipf("no UDP on %s: %s", ip, err)
	}
	defer capture.Close()
	if strings.Contains(ip, ":") {
		// The resolver refuses IPv6 unless the config enables it.
		disabled := resolver.DisableIPv6
		resolver.DisableIPv6 = false
		defer func() { resolver.DisableIPv6 = disabled }()
	}
	option.Name = "hysteria2_capture"
	option.Server = ip
	option.Port = capture.LocalAddr().(*net.UDPAddr).Port
	option.Password = userUUID
	option.Fingerprint = tlsFingerprint
	out, err := outbound.NewHysteria2(option)
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
	dcid := int(b[5])
	return n, int(b[6+dcid])
}
