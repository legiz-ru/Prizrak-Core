package inbound_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/component/ca"
	C "github.com/metacubex/mihomo/constant"

	"github.com/stretchr/testify/require"
)

// TestXHTTP3XrayServerSessionResumption: vless xhttp over HTTP/3 against
// Xray's xhttp inbound, with each browser's handshake and with
// disable-chrome-parrot. The QUIC connections are reused little (c-max-reuse-times: 1),
// and those after the first resume.
//
//	XRAY_BIN=/path/to/xray go test ./listener/inbound/ -run TestXHTTP3XrayServerSessionResumption -v
func TestXHTTP3XrayServerSessionResumption(t *testing.T) {
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

	port := reserveUDPPort(t)
	readyPort := vmessInteropReserveTCPPort(t)
	config, err := json.Marshal(map[string]any{
		"log": map[string]any{"loglevel": "warning"},
		"inbounds": []any{
			map[string]any{
				"listen": "127.0.0.1", "port": port, "protocol": "vless",
				"settings": map[string]any{"clients": []any{map[string]any{"id": userUUID}}, "decryption": "none"},
				"streamSettings": map[string]any{
					"network":       "xhttp",
					"xhttpSettings": map[string]any{"path": "/x"},
					"security":      "tls",
					"tlsSettings": map[string]any{
						"alpn":                    []string{"h3"},
						"certificates":            []any{map[string]any{"certificateFile": certFile, "keyFile": keyFile}},
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
			relay := newQUICRelay(t, fmt.Sprintf("127.0.0.1:%d", port))
			name := "xhttp3_xray_resumption_" + tc.name
			logs := watchQUICResumption(t, name)
			out, err := outbound.NewVless(outbound.VlessOption{
				Name:                    name,
				Server:                  "127.0.0.1",
				Port:                    relay.port(),
				UUID:                    userUUID,
				TLS:                     true,
				Network:                 "xhttp",
				ALPN:                    []string{"h3"},
				Fingerprint:             fingerprint,
				DisableChromeParrot:     tc.disable,
				ClientFingerprint:       tc.fingerprint,
				EnableSessionResumption: true,
				XHTTPOpts: outbound.XHTTPOptions{
					Path:          "/x",
					ReuseSettings: &outbound.XHTTPReuseSettings{CMaxReuseTimes: "1", MaxConnections: "1"},
				},
			})
			require.NoError(t, err)
			t.Cleanup(func() { _ = out.Close() })

			echoAddr := netip.MustParseAddrPort(tcpEcho)
			for i := 0; i < 4; i++ {
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
			}
			logs.wait(t, 2)
			logs.mu.Lock()
			lines := append([]string(nil), logs.lines...)
			logs.mu.Unlock()
			packets, sizes := relay.connections()
			t.Logf("handshakes: %q; 0-RTT packets %v, bytes %v", lines, packets, sizes)
			require.Len(t, sizes, len(lines))
			require.Equal(t, resumptionLine(false, false), lines[0])
			for i := 1; i < len(lines); i++ {
				require.True(t, strings.HasPrefix(lines[i], "TLS session resumed: true"), lines[i])
				require.Less(t, sizes[i], 200, "only the SETTINGS in 0-RTT")
			}
			checkQUICProfileInitials(t, relay, tc)
		})
	}
}
