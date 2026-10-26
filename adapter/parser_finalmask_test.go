package adapter

import (
	"testing"

	C "github.com/metacubex/mihomo/constant"
)

// A vless proxy with the finalmask chains of an Xray-core client, written as
// mihomo YAML would decode it.
func TestParseVlessFinalMask(t *testing.T) {
	proxy, err := ParseProxy(map[string]any{
		"name":             "vless-finalmask",
		"type":             "vless",
		"server":           "127.0.0.1",
		"port":             443,
		"uuid":             "b831381d-6324-4d53-ad4f-8cda48b30811",
		"network":          "xhttp",
		"tls":              true,
		"alpn":             []any{"h3"},
		"skip-cert-verify": true,
		"xhttp-opts":       map[string]any{"path": "/x"},
		"finalmask": map[string]any{
			"tcp": []any{
				map[string]any{"type": "fragment", "packets": "tlshello", "length": "100-200", "delay": "10-20"},
				map[string]any{"type": "header-custom", "clients": []any{[]any{
					map[string]any{"packet": "GET / HTTP/1.1\r\n", "type": "str"},
					map[string]any{"rand": 4, "rand-range": "48-57", "capture": "n"},
				}}, "servers": []any{[]any{
					map[string]any{"packet": "HTTP/1.1 200 OK\r\n", "type": "str"},
					map[string]any{"reuse": "n"},
				}}},
				map[string]any{"type": "sudoku", "password": "sudoku", "ascii": "prefer_ascii"},
			},
			"udp": []any{
				map[string]any{"type": "noise", "reset": "30-60", "noise": []any{
					map[string]any{"type": "exp", "packet": "<b 0x0d0a0d0a> <t> <r 24>", "delay": "10-20"},
					map[string]any{"rand": "40-60", "rand-range": "0-255"},
				}},
				map[string]any{"type": "udphop", "mode": "intervalLocal", "interval": "30-60"},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if proxy.Type() != C.Vless {
		t.Fatalf("type %v", proxy.Type())
	}

	// UDP masks need xhttp over HTTP/3.
	if _, err := ParseProxy(map[string]any{
		"name": "bad", "type": "vless", "server": "127.0.0.1", "port": 443, "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811",
		"finalmask": map[string]any{"udp": []any{map[string]any{"type": "noise", "noise": []any{map[string]any{"rand": 8}}}}},
	}); err == nil {
		t.Fatal("udp masks accepted on a tcp vless")
	}
	if _, err := ParseProxy(map[string]any{
		"name": "bad", "type": "vless", "server": "127.0.0.1", "port": 443, "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811",
		"finalmask": map[string]any{"tcp": []any{map[string]any{"type": "mkcp-legacy"}}},
	}); err == nil {
		t.Fatal("mkcp-legacy accepted")
	}
}

func TestParseTrojanFinalMask(t *testing.T) {
	proxy, err := ParseProxy(map[string]any{
		"name":             "trojan-finalmask",
		"type":             "trojan",
		"server":           "127.0.0.1",
		"port":             443,
		"password":         "secret",
		"skip-cert-verify": true,
		"finalmask": map[string]any{
			"tcp": []any{
				// Xray's nesting works too.
				map[string]any{"type": "xmc", "settings": map[string]any{
					"password": "p", "hostname": "mc.example.com",
					"profiles": []any{map[string]any{
						"username": "Steve", "uuid": "069a79f4-44e9-4726-a5be-fca90e38aaf5",
						"textures-value": "v", "textures-signature": "s",
					}},
				}},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if proxy.Type() != C.Trojan {
		t.Fatalf("type %v", proxy.Type())
	}
	if _, err := ParseProxy(map[string]any{
		"name": "bad", "type": "trojan", "server": "127.0.0.1", "port": 443, "password": "secret",
		"finalmask": map[string]any{"udp": []any{map[string]any{"type": "sudoku"}}},
	}); err == nil {
		t.Fatal("udp masks accepted on trojan")
	}
}
