package inbound_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/component/ca"
	C "github.com/metacubex/mihomo/constant"

	"github.com/stretchr/testify/require"
)

// The hysteria2 client against Xray's hysteria inbound, with each browser's
// QUIC handshake of client-fingerprint (Chrome's by default) and with
// disable-chrome-parrot, with and without salamander: TCP and UDP through
// Xray's freedom to local echo servers. Official Xray-core v26.9.8 and newer,
// or the fork:
//
//	XRAY_BIN=/path/to/xray go test ./listener/inbound/ -run TestHysteria2XrayServer -v
func TestHysteria2XrayServer(t *testing.T) {
	xrayBinary := os.Getenv("XRAY_BINARY")
	if xrayBinary == "" {
		xrayBinary = os.Getenv("XRAY_BIN")
	}
	if xrayBinary == "" {
		t.Skip("XRAY_BINARY is not set; point it at an Xray-core executable")
	}
	tcpEcho := startVMessInteropEcho(t)
	udpEcho := startUDPEcho(t)

	// Chrome offers no Ed25519 signature, so the certificate is ECDSA.
	certPEM, keyPEM, fingerprint, err := ca.NewRandomTLSKeyPair(ca.KeyPairTypeP256)
	require.NoError(t, err)
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	require.NoError(t, os.WriteFile(certFile, []byte(certPEM), 0o600))
	require.NoError(t, os.WriteFile(keyFile, []byte(keyPEM), 0o600))

	for _, obfs := range []string{"", "salamander"} {
		obfs := obfs
		hyPort := reserveUDPPort(t)
		readyPort := vmessInteropReserveTCPPort(t)
		stream := map[string]any{
			"network":          "hysteria",
			"hysteriaSettings": map[string]any{"version": 2},
			"security":         "tls",
			"tlsSettings": map[string]any{
				"alpn":         []string{"h3"},
				"certificates": []any{map[string]any{"certificateFile": certFile, "keyFile": keyFile}},
			},
		}
		if obfs != "" {
			stream["finalmask"] = map[string]any{"udp": []any{map[string]any{"type": "salamander", "settings": map[string]any{"password": "obfs-pw"}}}}
		}
		config, err := json.Marshal(map[string]any{
			"log": map[string]any{"loglevel": "warning"},
			"inbounds": []any{
				map[string]any{
					"listen": "127.0.0.1", "port": hyPort, "protocol": "hysteria",
					"settings":       map[string]any{"version": 2, "clients": []any{map[string]any{"auth": "pw", "email": "a@test"}}},
					"streamSettings": stream,
				},
				// Only for the readiness check: it listens on TCP.
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

		for _, profile := range quicProfileCases {
			profile := profile
			t.Run(fmt.Sprintf("obfs=%s/parrot=%s", obfs, profile.name), func(t *testing.T) {
				option := outbound.Hysteria2Option{
					Name:                "hysteria2_xray",
					Server:              "127.0.0.1",
					Port:                hyPort,
					Password:            "pw",
					Fingerprint:         fingerprint,
					DisableChromeParrot: profile.disable,
					ClientFingerprint:   profile.fingerprint,
				}
				if obfs != "" {
					option.Obfs, option.ObfsPassword = obfs, "obfs-pw"
				}
				out, err := outbound.NewHysteria2(option)
				require.NoError(t, err)
				defer out.Close()

				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				tcpAddr, err := netip.ParseAddrPort(tcpEcho)
				require.NoError(t, err)
				conn, err := out.DialContext(ctx, &C.Metadata{NetWork: C.TCP, DstIP: tcpAddr.Addr(), DstPort: tcpAddr.Port()})
				require.NoError(t, err)
				payload := make([]byte, 256*1024)
				_, _ = rand.Read(payload)
				go func() { _, _ = conn.Write(payload) }()
				got := make([]byte, len(payload))
				_ = conn.SetReadDeadline(time.Now().Add(20 * time.Second))
				_, err = io.ReadFull(conn, got)
				require.NoError(t, err)
				require.True(t, bytes.Equal(payload, got))
				_ = conn.Close()

				udpAddr, err := netip.ParseAddrPort(udpEcho)
				require.NoError(t, err)
				pc, err := out.ListenPacketContext(ctx, &C.Metadata{NetWork: C.UDP, DstIP: udpAddr.Addr(), DstPort: udpAddr.Port()})
				require.NoError(t, err)
				defer pc.Close()
				buf := make([]byte, 65536)
				for _, size := range hysteria2UDPSizes {
					msg := make([]byte, size)
					_, _ = rand.Read(msg)
					var echoed []byte
					for attempt := 0; attempt < 5 && echoed == nil; attempt++ {
						_, err := pc.WriteTo(msg, net.UDPAddrFromAddrPort(udpAddr))
						require.NoError(t, err)
						_ = pc.SetReadDeadline(time.Now().Add(2 * time.Second))
						n, _, err := pc.ReadFrom(buf)
						if err == nil {
							echoed = append([]byte(nil), buf[:n]...)
						}
					}
					require.NotNil(t, echoed, "no echo of %d bytes", size)
					require.True(t, bytes.Equal(msg, echoed), "echo of %d bytes came back as %d bytes", size, len(echoed))
				}
			})
		}
	}
}

func startUDPEcho(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		b := make([]byte, 65536)
		for {
			n, addr, err := pc.ReadFrom(b)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo(b[:n], addr)
		}
	}()
	return pc.LocalAddr().String()
}

func reserveUDPPort(t *testing.T) int {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	port := pc.LocalAddr().(*net.UDPAddr).Port
	require.NoError(t, pc.Close())
	return port
}
