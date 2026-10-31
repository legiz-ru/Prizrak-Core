package adapter

import (
	"fmt"
	"os"
	"testing"
)

// VLESS over mKCP against Xray-core, which since finalmask sends mKCP
// segments without a header of their own: plain, under UDP masks, and
// through an xdns tunnel with the small MTU a DNS tunnel needs.
//
//	XRAY_BIN=/path/to/xray go test ./adapter/ -run TestXrayMKCP -v
//
// The first xdns, the compact spelling of a resolver with its own framing
// on the wire, needs an Xray-core of that time (v26.6.x to v26.9.9):
//
//	XRAY_LEGACY_BIN=/path/to/xray-v26.6.27 go test ./adapter/ -run TestXrayMKCPLegacyXDNS -v

func mkcpProxy(port int, mtu int, finalmask map[string]any) map[string]any {
	proxy := map[string]any{
		"name": "vless-mkcp", "type": "vless", "server": "127.0.0.1", "port": port, "uuid": xrayUUID,
		"network": "mkcp", "udp": true, "packet-encoding": "xudp",
		"mkcp-opts": map[string]any{"mtu": mtu, "tti": 20, "congestion": false},
	}
	if len(finalmask) > 0 {
		proxy["finalmask"] = finalmask
	}
	return proxy
}

func mkcpStream(mtu int, finalmask map[string]any) map[string]any {
	stream := map[string]any{
		"network":     "kcp",
		"kcpSettings": map[string]any{"mtu": mtu, "tti": 20, "congestion": false},
	}
	if len(finalmask) > 0 {
		stream["finalmask"] = finalmask
	}
	return stream
}

func TestXrayMKCP(t *testing.T) {
	bin := xrayBinary(t)
	echoPort := echoServer(t)

	port := freePort(t, "udp")
	cases := []maskPair{{name: "plain"}}
	for _, pair := range udpMaskPairs(port) {
		switch pair.name {
		case "noise", "header-custom-prefix", "sudoku", "xdns":
			cases = append(cases, pair)
		}
	}
	for _, pair := range cases {
		pair := pair
		t.Run(pair.name, func(t *testing.T) {
			mtu := 1350
			if pair.name == "xdns" {
				mtu = 77
			}
			startXray(t, bin, xrayServer{proto: "vless", stream: mkcpStream(mtu, pair.xray), port: port, network: "udp", readyTCP: freePort(t, "tcp")})
			proxy, err := ParseProxy(mkcpProxy(port, mtu, pair.core))
			if err != nil {
				t.Fatal(err)
			}
			defer proxy.Close()
			size := 64 * 1024
			if pair.name == "xdns" {
				size = 8 * 1024
			}
			echoThrough(t, proxy, echoPort, size)
		})
	}
}

func TestXrayMKCPLegacyXDNS(t *testing.T) {
	bin := os.Getenv("XRAY_LEGACY_BIN")
	if bin == "" {
		t.Skip("XRAY_LEGACY_BIN not set; skipping the first-xdns interop test")
	}
	if _, err := os.Stat(bin); err != nil {
		t.Skipf("XRAY_LEGACY_BIN %s: %v", bin, err)
	}
	echoPort := echoServer(t)
	port := freePort(t, "udp")
	for _, method := range []string{"txt", "aaaa"} {
		method := method
		t.Run(method, func(t *testing.T) {
			zone := "t.example.com:" + method
			server := map[string]any{"udp": []any{map[string]any{"type": "xdns", "settings": map[string]any{"domains": []any{zone}}}}}
			client := map[string]any{"udp": []any{map[string]any{"type": "xdns", "settings": map[string]any{"resolvers": []any{
				fmt.Sprintf("%s+udp://127.0.0.1:%d", zone, port),
				fmt.Sprintf("%s+udp://127.0.0.1:%d", zone, port),
			}}}}}
			startXray(t, bin, xrayServer{proto: "vless", stream: mkcpStream(77, server), port: port, network: "udp", readyTCP: freePort(t, "tcp")})
			proxy, err := ParseProxy(mkcpProxy(port, 77, client))
			if err != nil {
				t.Fatal(err)
			}
			defer proxy.Close()
			echoThrough(t, proxy, echoPort, 8*1024)
		})
	}
}
