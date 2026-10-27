package adapter

import (
	"testing"
)

// TestXrayXHTTPUplinkGET sends the packet-up uploads with GET, as Xray's
// uplinkHTTPMethod: "GET" does, to the Xray-core fork's xhttp inbound, with
// the data in the body, in headers and in cookies. Needs XRAY_BINARY, see
// finalmask_xray_test.go.
func TestXrayXHTTPUplinkGET(t *testing.T) {
	bin := xrayBinary(t)
	echoPort := echoServer(t)
	certFile, keyFile := writeCert(t, t.TempDir())

	for _, method := range []string{"POST", "GET"} {
		for _, placement := range []string{"body", "header", "cookie"} {
			method, placement := method, placement
			t.Run(method+"/"+placement, func(t *testing.T) {
				stream := map[string]any{
					"network":       "xhttp",
					"xhttpSettings": map[string]any{"path": "/x", "mode": "packet-up", "uplinkDataPlacement": placement},
				}
				for k, v := range tlsStream(certFile, keyFile, nil) {
					stream[k] = v
				}
				port := freePort(t, "tcp")
				startXray(t, bin, xrayServer{proto: "vless", stream: stream, port: port, readyTCP: freePort(t, "tcp")})

				proxy, err := ParseProxy(map[string]any{
					"name": "vless-xhttp-get", "type": "vless", "server": "127.0.0.1", "port": port, "uuid": xrayUUID,
					"network": "xhttp", "tls": true, "servername": "localhost", "skip-cert-verify": true,
					"xhttp-opts": map[string]any{
						"path": "/x", "mode": "packet-up",
						"uplink-http-method":    method,
						"uplink-data-placement": placement,
					},
				})
				if err != nil {
					t.Fatal(err)
				}
				defer proxy.Close()
				echoThrough(t, proxy, echoPort, 256*1024)
			})
		}
	}
}
