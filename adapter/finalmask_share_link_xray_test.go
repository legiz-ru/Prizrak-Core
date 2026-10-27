package adapter

import (
	"context"
	"encoding/json"
	"io"
	"net/netip"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/metacubex/mihomo/common/convert"
	C "github.com/metacubex/mihomo/constant"
)

// The masks arrive by subscription: a vless:// link with fm=<JSON> as the
// Remnawave backend writes it, and the Xray JSON subscription with the same
// finalmask in streamSettings. Both go through the converters, then through
// the Xray fork with those masks on its inbound. Needs XRAY_BINARY.
func TestXrayFinalMaskSubscription(t *testing.T) {
	bin := xrayBinary(t)
	echoPort := echoServer(t)
	certFile, keyFile := writeCert(t, t.TempDir())

	// The chain as Xray writes it (settings nested, camelCase keys), the
	// form a subscription carries.
	chain := map[string]any{"tcp": []any{
		map[string]any{"type": "header-custom", "settings": map[string]any{
			"clients": []any{[]any{
				map[string]any{"type": "str", "packet": "GET /api HTTP/1.1\r\nHost: cdn.example.com\r\nX-Nonce: "},
				map[string]any{"rand": 8, "randRange": "97-122", "capture": "nonce"},
				map[string]any{"type": "str", "packet": "\r\n\r\n"},
			}},
			"servers": []any{[]any{
				map[string]any{"type": "str", "packet": "HTTP/1.1 101 Switching Protocols\r\nX-Nonce: "},
				map[string]any{"reuse": "nonce"},
				map[string]any{"type": "str", "packet": "\r\n\r\n"},
			}},
		}},
		map[string]any{"type": "fragment", "settings": map[string]any{"packets": "tlshello", "lengths": []any{"5-10", "100-200"}, "delays": []any{"1-2", "0"}, "maxSplit": "3-6"}},
		map[string]any{"type": "sudoku", "settings": map[string]any{"password": "sub-pw", "customTables": []any{"xpxvvpvv"}, "paddingMin": 10, "paddingMax": 30}},
	}}
	fmJSON, err := json.Marshal(chain)
	if err != nil {
		t.Fatal(err)
	}

	stream := map[string]any{"network": "tcp", "finalmask": chain}
	for k, v := range tlsStream(certFile, keyFile, nil) {
		stream[k] = v
	}
	port := freePort(t, "tcp")
	startXray(t, bin, xrayServer{proto: "vless", stream: stream, port: port, readyTCP: freePort(t, "tcp")})

	t.Run("link", func(t *testing.T) {
		link := "vless://" + xrayUUID + "@127.0.0.1:" + itoa(port) + "?encryption=none&type=tcp&security=tls&sni=localhost&fp=chrome&allowInsecure=1&fm=" + url.QueryEscape(string(fmJSON)) + "#masked?serverDescription=bWFza2Vk"
		proxies, err := convert.ConvertsV2Ray([]byte(link))
		if err != nil {
			t.Fatal(err)
		}
		proxies[0]["skip-cert-verify"] = true
		if proxies[0]["serverDescription"] != "masked" {
			t.Fatalf("serverDescription = %v", proxies[0]["serverDescription"])
		}
		proxy, err := ParseProxy(proxies[0])
		if err != nil {
			t.Fatal(err)
		}
		defer proxy.Close()
		echoThrough(t, proxy, echoPort, 256*1024)
	})

	t.Run("xray-json", func(t *testing.T) {
		sub := []any{map[string]any{
			"remarks": "masked",
			"meta":    map[string]any{"serverDescription": "masked"},
			"outbounds": []any{
				map[string]any{
					"tag": "proxy", "protocol": "vless",
					"settings": map[string]any{"vnext": []any{map[string]any{
						"address": "127.0.0.1", "port": port,
						"users": []any{map[string]any{"id": xrayUUID, "encryption": "none", "flow": ""}},
					}}},
					"streamSettings": map[string]any{
						"network": "tcp", "tcpSettings": map[string]any{},
						"security":    "tls",
						"tlsSettings": map[string]any{"serverName": "localhost", "fingerprint": "chrome", "allowInsecure": true},
						"finalmask":   chain,
					},
				},
				map[string]any{"tag": "direct", "protocol": "freedom", "settings": map[string]any{}},
			},
		}}
		data, err := json.Marshal(sub)
		if err != nil {
			t.Fatal(err)
		}
		proxies, err := convert.ConvertsXrayJSON(data)
		if err != nil {
			t.Fatal(err)
		}
		if proxies[0]["skip-cert-verify"] != true || proxies[0]["serverDescription"] != "masked" {
			t.Fatalf("converted proxy: %v", proxies[0])
		}
		proxy, err := ParseProxy(proxies[0])
		if err != nil {
			t.Fatal(err)
		}
		defer proxy.Close()
		echoThrough(t, proxy, echoPort, 256*1024)
	})

	// The same link without masks must not get through: the masks are what
	// the server speaks.
	t.Run("link-without-fm", func(t *testing.T) {
		link := "vless://" + xrayUUID + "@127.0.0.1:" + itoa(port) + "?encryption=none&type=tcp&security=tls&sni=localhost#plain"
		proxies, err := convert.ConvertsV2Ray([]byte(link))
		if err != nil {
			t.Fatal(err)
		}
		proxies[0]["skip-cert-verify"] = true
		proxy, err := ParseProxy(proxies[0])
		if err != nil {
			t.Fatal(err)
		}
		defer proxy.Close()
		expectNoEcho(t, proxy, echoPort)
	})
}

func itoa(n int) string { return strconv.Itoa(n) }

// expectNoEcho checks that nothing comes back through the proxy: the dial
// fails, or the echo does not arrive.
func expectNoEcho(t *testing.T, proxy C.Proxy, echoPort int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := proxy.DialContext(ctx, &C.Metadata{NetWork: C.TCP, DstIP: netip.MustParseAddr("127.0.0.1"), DstPort: uint16(echoPort)})
	if err != nil {
		return
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	go func() { _, _ = conn.Write([]byte("ping")) }()
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err == nil && string(buf) == "ping" {
		t.Fatal("the echo came through without the masks")
	}
}
