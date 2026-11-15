package adapter

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/ech"
	C "github.com/metacubex/mihomo/constant"
)

// captureFirstInitial dials proxy at a socket that never answers, whose port
// the proxy is configured with, and returns the size and the source
// connection ID length of the first datagram, an Initial.
func captureFirstInitial(t *testing.T, mapping func(port int) map[string]any) (size, scid int) {
	t.Helper()
	capture, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer capture.Close()
	proxy, err := ParseProxy(mapping(capture.LocalAddr().(*net.UDPAddr).Port))
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go func() {
		_, _ = proxy.DialContext(ctx, &C.Metadata{NetWork: C.TCP, DstIP: netip.MustParseAddr("127.0.0.1"), DstPort: 80})
	}()
	b := make([]byte, 65536)
	_ = capture.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, _, err := capture.ReadFromUDP(b)
	if err != nil {
		t.Fatal(err)
	}
	if n < 8 || b[0]&0x80 == 0 || b[0]&0x30 != 0 {
		t.Fatal("not a long header Initial")
	}
	return n, int(b[6+int(b[5])])
}

// vless parrots a browser's QUIC handshake for xhttp over HTTP/3 by default,
// the browser of client-fingerprint (Firefox's names Firefox, Safari's Safari
// without ECH, any other value Chrome), and quic-go's own with
// disable-chrome-parrot.
func TestVlessXHTTP3QUICProfile(t *testing.T) {
	for _, tc := range []struct {
		disable     bool
		fingerprint string
		size, scid  int
	}{
		{true, "firefox", 1280, 0},
		{false, "", 1250, 0},
		{false, "chrome", 1250, 0},
		{false, "firefox", 1252, 3},
		{false, "safari", 1200, 0},
		{false, "ios", 1250, 0},
		{false, "random", 1250, 0},
	} {
		size, scid := captureFirstInitial(t, func(port int) map[string]any {
			m := map[string]any{
				"name": "vless-h3", "type": "vless", "server": "127.0.0.1", "port": port, "uuid": xrayUUID,
				"network": "xhttp", "xhttp-opts": map[string]any{"path": "/x"},
				"tls": true, "alpn": []any{"h3"}, "servername": "localhost", "skip-cert-verify": true,
			}
			if tc.fingerprint != "" {
				m["client-fingerprint"] = tc.fingerprint
			}
			if tc.disable {
				m["disable-chrome-parrot"] = true
			}
			return m
		})
		if size != tc.size || scid != tc.scid {
			t.Errorf("disable-chrome-parrot %v, %q: size %d, scid %d; want %d, %d", tc.disable, tc.fingerprint, size, scid, tc.size, tc.scid)
		}
	}
	// The captured Safari hello has no ECH: with ech-opts, Chrome's.
	echConfig, _, err := ech.GenECHConfig("public.example")
	if err != nil {
		t.Fatal(err)
	}
	size, scid := captureFirstInitial(t, func(port int) map[string]any {
		return map[string]any{
			"name": "vless-h3-ech", "type": "vless", "server": "127.0.0.1", "port": port, "uuid": xrayUUID,
			"network": "xhttp", "xhttp-opts": map[string]any{"path": "/x"},
			"tls": true, "alpn": []any{"h3"}, "servername": "localhost", "skip-cert-verify": true,
			"client-fingerprint": "safari", "ech-opts": map[string]any{"enable": true, "config": echConfig},
		}
	})
	if size != 1250 || scid != 0 {
		t.Errorf("safari with ECH: size %d, scid %d; want Chrome's 1250, 0", size, scid)
	}
}

// xdrive over HTTP/3 dials the storage service with the same handshake: by
// default the browser's of client-fingerprint, with disable-chrome-parrot
// quic-go's own.
func TestVlessXDriveH3QUICProfile(t *testing.T) {
	for _, tc := range []struct {
		disable     bool
		fingerprint string
		size, scid  int
	}{
		{true, "firefox", 1280, 0},
		{false, "", 1250, 0},
		{false, "firefox", 1252, 3},
	} {
		size, scid := captureFirstInitial(t, func(port int) map[string]any {
			base := fmt.Sprintf("https://127.0.0.1:%d/{folder}", port)
			m := map[string]any{
				"name": "vless-xdrive-h3", "type": "vless", "server": "127.0.0.1", "port": 443, "uuid": xrayUUID,
				"encryption": xdriveTestEncryption, "network": "xdrive", "alpn": []any{"h3"}, "skip-cert-verify": true,
				"mux.cool": map[string]any{"enabled": true},
				"xdrive-opts": map[string]any{"service": "template", "remote-folder": "f", "template": map[string]any{
					"put":    map[string]any{"method": "PUT", "url": base + "/{name}"},
					"get":    map[string]any{"method": "GET", "url": base + "/{name}"},
					"delete": map[string]any{"method": "DELETE", "url": base + "/{name}"},
					"list":   map[string]any{"method": "GET", "url": base + "?list={prefix}", "namesRegex": `"([^"]+)"`},
				}},
			}
			if tc.fingerprint != "" {
				m["client-fingerprint"] = tc.fingerprint
			}
			if tc.disable {
				m["disable-chrome-parrot"] = true
			}
			return m
		})
		if size != tc.size || scid != tc.scid {
			t.Errorf("disable-chrome-parrot %v, %q: size %d, scid %d; want %d, %d", tc.disable, tc.fingerprint, size, scid, tc.size, tc.scid)
		}
	}
}
