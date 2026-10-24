package adapter

import (
	"testing"

	C "github.com/metacubex/mihomo/constant"
)

// The freedom outbound of the Xray-core example, written as a mihomo proxy.
func TestParseFreedom(t *testing.T) {
	proxy, err := ParseProxy(map[string]any{
		"name": "FRAGMENT",
		"type": "freedom",
		"fragment": map[string]any{
			"interval": 0,
			"length":   "1-1",
			"packets":  "tlshello",
		},
		"sockopt": map[string]any{
			"custom-sockopt": []any{
				map[string]any{"opt": "1", "type": "int", "value": 1},
			},
			"tcp-congestion":          "bbr",
			"tcp-keep-alive-idle":     300,
			"tcp-keep-alive-interval": 60,
			"tcp-user-timeout":        10000,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if proxy.Name() != "FRAGMENT" || proxy.Type() != C.Freedom || proxy.Type().String() != "Freedom" || !proxy.SupportUDP() {
		t.Fatalf("parsed %s %s udp=%v", proxy.Name(), proxy.Type(), proxy.SupportUDP())
	}

	if _, err := ParseProxy(map[string]any{
		"name": "bad", "type": "freedom",
		"fragment": map[string]any{"packets": "tlshello", "split": "nope"},
	}); err == nil {
		t.Fatal("unknown split mode accepted")
	}
}
