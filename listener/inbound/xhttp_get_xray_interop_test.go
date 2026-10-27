package inbound_test

import (
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"testing"

	"github.com/metacubex/mihomo/listener/inbound"

	"github.com/stretchr/testify/require"
)

// The Xray-core fork as an xhttp client with uplinkHTTPMethod GET and the
// data in the body, in headers or in cookies, a Prizrak-Core xhttp inbound
// as the server. Needs XRAY_BINARY, see finalmask_xray_interop_test.go.
func TestXHTTPUplinkGETXrayClientToMihomoServer(t *testing.T) {
	xrayBinary := os.Getenv("XRAY_BINARY")
	if xrayBinary == "" {
		xrayBinary = os.Getenv("XRAY_BIN")
	}
	if xrayBinary == "" {
		t.Skip("XRAY_BINARY is not set; point it at the Xray-core fork's executable")
	}
	echoAddr := startVMessInteropEcho(t)
	targetHost, targetPort, err := net.SplitHostPort(echoAddr)
	require.NoError(t, err)
	targetPortNumber, err := net.LookupPort("tcp", targetPort)
	require.NoError(t, err)

	for _, placement := range []string{"body", "header", "cookie"} {
		placement := placement
		t.Run(placement, func(t *testing.T) {
			in, err := inbound.NewVless(&inbound.VlessOption{
				BaseOption:    inbound.BaseOption{NameStr: "vless_xhttp_get_xray", Listen: "127.0.0.1", Port: "0"},
				Users:         []inbound.VlessUser{{Username: "xray", UUID: finalMaskXrayUUID}},
				AllowInsecure: true,
				XHTTPConfig:   inbound.XHTTPConfig{Path: "/x", Mode: "packet-up", UplinkDataPlacement: placement},
			})
			require.NoError(t, err)
			require.NoError(t, in.Listen(vmessInteropDirectTunnel(t)))
			t.Cleanup(func() { _ = in.Close() })
			mihomoAddr, err := netip.ParseAddrPort(in.Address())
			require.NoError(t, err)

			xrayPort := vmessInteropReserveTCPPort(t)
			config := map[string]any{
				"log": map[string]any{"loglevel": "debug"},
				"inbounds": []any{map[string]any{
					"listen": "127.0.0.1", "port": xrayPort.Port(), "protocol": "dokodemo-door",
					"settings": map[string]any{"address": targetHost, "port": targetPortNumber, "network": "tcp"},
				}},
				"outbounds": []any{map[string]any{
					"protocol": "vless",
					"settings": map[string]any{"vnext": []any{map[string]any{
						"address": "127.0.0.1", "port": int(mihomoAddr.Port()),
						"users": []any{map[string]any{"id": finalMaskXrayUUID, "encryption": "none"}},
					}}},
					"streamSettings": map[string]any{
						"network":  "xhttp",
						"security": "none",
						"xhttpSettings": map[string]any{
							"path": "/x", "mode": "packet-up",
							"uplinkHTTPMethod":    "GET",
							"uplinkDataPlacement": placement,
						},
					},
				}},
			}
			data, err := json.MarshalIndent(config, "", "  ")
			require.NoError(t, err)
			startXrayRealityServer(t, xrayBinary, append(data, '\n'), xrayPort)

			vmessInteropRoundTripWithRetry(t, func() (net.Conn, error) {
				return net.Dial("tcp", net.JoinHostPort("127.0.0.1", fmt.Sprint(xrayPort.Port())))
			}, 128*1024)
		})
	}
}
