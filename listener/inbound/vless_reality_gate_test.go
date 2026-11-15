package inbound_test

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter/outbound"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener/inbound"

	utls "github.com/metacubex/utls"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/hkdf"
)

// The REALITY server accepts every client fingerprint by default: a Client
// Hello that offers no X25519MLKEM768 at all ("ios", "edge") authenticates
// with its X25519 key share. require-mlkem accepts only hellos that
// authenticate through X25519MLKEM768.
func TestInboundVless_RealityClientFingerprints(t *testing.T) {
	testCases := []struct {
		fingerprint string
		hybrid      bool
	}{
		{fingerprint: "chrome", hybrid: true},
		{fingerprint: "firefox", hybrid: true},
		{fingerprint: "safari", hybrid: true},
		{fingerprint: "ios"},
		{fingerprint: "edge"},
	}
	for _, requireMLKEM := range []bool{false, true} {
		for _, testCase := range testCases {
			requireMLKEM, testCase := requireMLKEM, testCase
			name := testCase.fingerprint
			if requireMLKEM {
				name += "/require-mlkem"
			}
			t.Run(name, func(t *testing.T) {
				t.Parallel()
				reality := realityGateConfig()
				reality.RequireMLKEM = requireMLKEM
				tunnel, addr := startRealityGateInbound(t, reality)
				out := newRealityGateOutbound(t, tunnel, addr, testCase.fingerprint)
				if accepted := testCase.hybrid || !requireMLKEM; accepted {
					tunnel.DoSequentialTest(t, out)
				} else {
					requireRealityRefused(t, out)
				}
			})
		}
	}
}

// min-client-ver and max-client-ver are off unless set, so a client that
// sends an old REALITY version such as 1.8.2 (plain mihomo) is accepted; set,
// they bound the client version.
func TestInboundVless_RealityClientVersion(t *testing.T) {
	ourVersion := [3]byte{26, 11, 10}
	testCases := []struct {
		name     string
		min, max string
		version  [3]byte
		accepted bool
	}{
		{name: "1.8.2 without bounds", version: [3]byte{1, 8, 2}, accepted: true},
		{name: "0.0.0 without bounds", version: [3]byte{0, 0, 0}, accepted: true},
		{name: "1.8.2 below min", min: "26.3.27", version: [3]byte{1, 8, 2}},
		{name: "1.8.2 at min", min: "1.8.2", version: [3]byte{1, 8, 2}, accepted: true},
		{name: "26.11.10 at min", min: "26.11.10", version: ourVersion, accepted: true},
		{name: "26.11.10 below min", min: "26.11.11", version: ourVersion},
		{name: "26.11.10 at max", max: "26.11.10", version: ourVersion, accepted: true},
		{name: "26.11.10 above max", max: "26.11.9", version: ourVersion},
	}
	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			reality := realityGateConfig()
			reality.MinClientVersion = testCase.min
			reality.MaxClientVersion = testCase.max
			_, addr := startRealityGateInbound(t, reality)
			for _, fingerprint := range []utls.ClientHelloID{utls.HelloChrome_Auto, utls.HelloIOS_Auto} {
				if got := realityGateHandshake(t, addr, fingerprint, testCase.version); got != testCase.accepted {
					t.Fatalf("%s: REALITY authenticated = %v, want %v", fingerprint.Str(), got, testCase.accepted)
				}
			}
		})
	}

}

func realityGateConfig() inbound.RealityConfig {
	return inbound.RealityConfig{
		Dest:        net.JoinHostPort(realityDest, "443"),
		PrivateKey:  realityPrivateKey,
		ShortID:     []string{realityShortid},
		ServerNames: []string{realityDest},
	}
}

func startRealityGateInbound(t *testing.T, reality inbound.RealityConfig) (*TestTunnel, netip.AddrPort) {
	t.Helper()
	in, err := inbound.NewVless(&inbound.VlessOption{
		BaseOption:    inbound.BaseOption{NameStr: "vless_reality_gate", Listen: "127.0.0.1", Port: "0"},
		Users:         []inbound.VlessUser{{Username: "test", UUID: userUUID}},
		RealityConfig: reality,
	})
	require.NoError(t, err)
	tunnel := NewHttpTestTunnel()
	t.Cleanup(func() { _ = tunnel.Close() })
	require.NoError(t, in.Listen(tunnel))
	t.Cleanup(func() { _ = in.Close() })
	addr, err := netip.ParseAddrPort(in.Address())
	require.NoError(t, err)
	return tunnel, addr
}

func newRealityGateOutbound(t *testing.T, tunnel *TestTunnel, addr netip.AddrPort, fingerprint string) *outbound.Vless {
	t.Helper()
	options := outbound.VlessOption{
		Name:              "vless_reality_gate",
		Server:            addr.Addr().String(),
		Port:              int(addr.Port()),
		UUID:              userUUID,
		TLS:               true,
		ServerName:        realityDest,
		ClientFingerprint: fingerprint,
		RealityOpts: outbound.RealityOptions{
			PublicKey: realityPublickey,
			ShortID:   realityShortid,
		},
	}
	options.DialerForAPI = tunnel.NewDialer()
	options.TunnelForAPI = tunnel
	out, err := outbound.NewVless(options)
	require.NoError(t, err)
	t.Cleanup(func() { _ = out.Close() })
	return out
}

func requireRealityRefused(t *testing.T, out *outbound.Vless) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := out.DialContext(ctx, &C.Metadata{NetWork: C.TCP, DstIP: remoteAddr, DstPort: 80})
	if err == nil {
		_ = conn.Close()
		t.Fatal("the REALITY server authenticated the client")
	}
	// The server forwarded the client to the target, whose certificate the
	// client either verifies (and then gives up) or rejects for its name.
	if message := err.Error(); !strings.Contains(message, "REALITY authentication failed") && !strings.Contains(message, "x509:") {
		t.Fatalf("dial error = %v, want one from a client the server forwarded to the target", err)
	}
}

// realityGateHandshake performs a REALITY client handshake that sends
// version, and reports whether the server presented the certificate that
// proves it authenticated the client.
func realityGateHandshake(t *testing.T, addr netip.AddrPort, fingerprint utls.ClientHelloID, version [3]byte) bool {
	t.Helper()
	publicKeyBytes, err := base64.RawURLEncoding.DecodeString(realityPublickey)
	require.NoError(t, err)
	publicKey, err := ecdh.X25519().NewPublicKey(publicKeyBytes)
	require.NoError(t, err)
	var shortID [8]byte
	_, err = hex.Decode(shortID[:], []byte(realityShortid))
	require.NoError(t, err)

	conn, err := net.DialTimeout("tcp", addr.String(), 5*time.Second)
	require.NoError(t, err)
	defer conn.Close()
	require.NoError(t, conn.SetDeadline(time.Now().Add(10*time.Second)))

	uConn := utls.UClient(conn, &utls.Config{
		ServerName:             realityDest,
		InsecureSkipVerify:     true,
		SessionTicketsDisabled: true,
	}, fingerprint)
	require.NoError(t, uConn.BuildHandshakeState())
	hello := uConn.HandshakeState.Hello
	for i := 39; i < 39+32; i++ {
		hello.Raw[i] = 0
	}
	binary.BigEndian.PutUint64(hello.SessionId, uint64(time.Now().Unix()))
	copy(hello.SessionId[:3], version[:])
	copy(hello.SessionId[8:], shortID[:])

	keys := uConn.HandshakeState.State13.KeyShareKeys
	require.NotNil(t, keys)
	key := keys.Ecdhe
	if key == nil || key.Curve() != ecdh.X25519() {
		key = keys.MlkemEcdhe
	}
	require.NotNil(t, key)
	authKey, err := key.ECDH(publicKey)
	require.NoError(t, err)
	_, err = hkdf.New(sha256.New, authKey, hello.Random[:20], []byte("REALITY")).Read(authKey)
	require.NoError(t, err)
	block, err := aes.NewCipher(authKey)
	require.NoError(t, err)
	aead, err := cipher.NewGCM(block)
	require.NoError(t, err)
	aead.Seal(hello.SessionId[:0], hello.Random[20:], hello.SessionId[:16], hello.Raw)
	copy(hello.Raw[39:], hello.SessionId)

	require.NoError(t, uConn.Handshake())
	certificates := uConn.ConnectionState().PeerCertificates
	require.NotEmpty(t, certificates)
	publicKeyOfCertificate, ok := certificates[0].PublicKey.(ed25519.PublicKey)
	if !ok {
		return false
	}
	mac := hmac.New(sha512.New, authKey)
	mac.Write(publicKeyOfCertificate)
	return bytes.Equal(mac.Sum(nil), certificates[0].Signature)
}
