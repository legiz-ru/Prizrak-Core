package adapter

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	stdtls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/dialer"
	C "github.com/metacubex/mihomo/constant"
)

// These tests run the Xray-core fork as the server (an inbound with
// finalmask) and Prizrak-Core as the client (a proxy with the same masks),
// which is what the port is for. They need the fork's binary:
//
//	XRAY_BIN=/path/to/xray go test ./adapter/ -run TestXrayFinalMask -v
//
// and are skipped without it.

const (
	xrayUUID       = "b831381d-6324-4d53-ad4f-8cda48b30811"
	xrayVisionUUID = "5a7f0d2c-3b4e-4f61-8a9b-0c1d2e3f4a5b" // declared with flow xtls-rprx-vision
	xrayPassword   = "trojan-password"
)

func xrayBinary(t *testing.T) string {
	t.Helper()
	bin := os.Getenv("XRAY_BINARY")
	if bin == "" {
		bin = os.Getenv("XRAY_BIN")
	}
	if bin == "" {
		t.Skip("XRAY_BIN not set; skipping the Xray-core interop test")
	}
	if _, err := os.Stat(bin); err != nil {
		t.Skipf("XRAY_BIN %s: %v", bin, err)
	}
	return bin
}

func freePort(t *testing.T, network string) int {
	t.Helper()
	if network == "udp" {
		c, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		return c.LocalAddr().(*net.UDPAddr).Port
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// writeCert writes a self-signed certificate for localhost.
func writeCert(t *testing.T, dir string) (certFile, keyFile string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certFile = filepath.Join(dir, "cert.pem")
	keyFile = filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile
}

// echoServer echoes every byte it gets; it is what the proxied connection
// reaches through Xray's freedom outbound.
func echoServer(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

type xrayServer struct {
	proto    string         // vless or trojan
	stream   map[string]any // streamSettings
	port     int
	network  string // tcp or udp: what the inbound listens on
	readyTCP int    // a socks inbound to wait for
}

// startXray writes the config and runs the binary until the test ends.
func startXray(t *testing.T, bin string, s xrayServer) {
	t.Helper()
	dir := t.TempDir()
	settings := map[string]any{}
	switch s.proto {
	case "vless":
		settings = map[string]any{"clients": []any{
			map[string]any{"id": xrayUUID},
			map[string]any{"id": xrayVisionUUID, "flow": "xtls-rprx-vision"},
		}, "decryption": "none"}
	case "trojan":
		settings = map[string]any{"clients": []any{map[string]any{"password": xrayPassword}}}
	}
	logFile := filepath.Join(dir, "xray.log")
	cfg := map[string]any{
		"log": map[string]any{"loglevel": "debug", "error": logFile, "access": logFile},
		"inbounds": []any{
			map[string]any{
				"listen": "127.0.0.1", "port": s.port, "protocol": s.proto,
				"settings": settings, "streamSettings": s.stream,
			},
			map[string]any{"listen": "127.0.0.1", "port": s.readyTCP, "protocol": "socks", "settings": map[string]any{}},
		},
		// The fork's freedom blocks loopback targets unless a rule allows them.
		"outbounds": []any{map[string]any{"protocol": "freedom", "settings": map[string]any{
			"finalRules": []any{map[string]any{"action": "allow", "ip": []any{"127.0.0.1/32"}}},
		}}},
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	cfgFile := filepath.Join(dir, "config.json")
	if err := os.WriteFile(cfgFile, data, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "run", "-c", cfgFile)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		if t.Failed() {
			log, _ := os.ReadFile(logFile)
			t.Logf("xray config:\n%s\nxray output:\n%s\nxray log:\n%s", data, out.String(), log)
		}
	})
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", s.readyTCP), 200*time.Millisecond)
		if err == nil {
			c.Close()
			// The masked inbound comes up with the socks one; give the UDP
			// one a moment.
			time.Sleep(200 * time.Millisecond)
			return
		}
		if cmd.ProcessState != nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	log, _ := os.ReadFile(logFile)
	t.Fatalf("xray did not start:\n%s\n%s\n%s", data, out.String(), log)
}

// echoThrough dials the echo server through the proxy and checks a transfer
// both ways, twice, so a connection after the first works as well.
func echoThrough(t *testing.T, proxy C.Proxy, echoPort int, size int) {
	t.Helper()
	for i := 0; i < 2; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		conn, err := proxy.DialContext(ctx, &C.Metadata{
			NetWork: C.TCP,
			DstIP:   netip.MustParseAddr("127.0.0.1"),
			DstPort: uint16(echoPort),
		})
		if err != nil {
			cancel()
			t.Fatalf("dial %d: %v", i, err)
		}
		_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
		payload := make([]byte, size)
		_, _ = rand.Read(payload)
		writeErr := make(chan error, 1)
		go func() {
			_, err := conn.Write(payload)
			writeErr <- err
		}()
		got := make([]byte, size)
		if _, err := io.ReadFull(conn, got); err != nil {
			cancel()
			t.Fatalf("read %d: %v", i, err)
		}
		if err := <-writeErr; err != nil {
			cancel()
			t.Fatalf("write %d: %v", i, err)
		}
		if !bytes.Equal(payload, got) {
			cancel()
			t.Fatalf("echo %d differs", i)
		}
		conn.Close()
		cancel()
	}
}

// Xray's finalmask JSON and the mihomo finalmask block of the same masks,
// as a user would write them on each side.
type maskPair struct {
	name string
	xray map[string]any // finalmask of the inbound's streamSettings
	core map[string]any // finalmask of the proxy
}

func xmcProfile() (map[string]any, map[string]any) {
	xray := map[string]any{
		"username": "Steve_01", "uuid": "069a79f4-44e9-4726-a5be-fca90e38aaf5",
		"texturesValue": strings.Repeat("texture-value-", 40), "texturesSignature": strings.Repeat("texture-signature-", 24),
	}
	core := map[string]any{
		"username": "Steve_01", "uuid": "069a79f4-44e9-4726-a5be-fca90e38aaf5",
		"textures-value": strings.Repeat("texture-value-", 40), "textures-signature": strings.Repeat("texture-signature-", 24),
	}
	return xray, core
}

func tcpMaskPairs() []maskPair {
	xmcXray, xmcCore := xmcProfile()
	return []maskPair{
		{
			// A control: the harness itself, without masks.
			name: "none",
			xray: map[string]any{},
			core: map[string]any{},
		},
		{
			name: "fragment-tlshello",
			xray: map[string]any{"tcp": []any{map[string]any{"type": "fragment", "settings": map[string]any{"packets": "tlshello", "length": "20-60", "delay": "0"}}}},
			core: map[string]any{"tcp": []any{map[string]any{"type": "fragment", "packets": "tlshello", "length": "20-60", "delay": 0}}},
		},
		{
			name: "fragment-packets-lengths",
			xray: map[string]any{"tcp": []any{map[string]any{"type": "fragment", "settings": map[string]any{"packets": "1-3", "lengths": []any{"5-10", "100-200"}, "delays": []any{"1-2", "0"}}}}},
			core: map[string]any{"tcp": []any{map[string]any{"type": "fragment", "packets": "1-3", "lengths": []any{"5-10", "100-200"}, "delays": []any{"1-2", 0}}}},
		},
		{
			name: "header-custom-http",
			xray: map[string]any{"tcp": []any{map[string]any{"type": "header-custom", "settings": map[string]any{
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
				"errors": []any{[]any{map[string]any{"type": "str", "packet": "HTTP/1.1 404 Not Found\r\n\r\n"}}},
			}}}},
			core: map[string]any{"tcp": []any{map[string]any{"type": "header-custom",
				"clients": []any{[]any{
					map[string]any{"type": "str", "packet": "GET /api HTTP/1.1\r\nHost: cdn.example.com\r\nX-Nonce: "},
					map[string]any{"rand": 8, "rand-range": "97-122", "capture": "nonce"},
					map[string]any{"type": "str", "packet": "\r\n\r\n"},
				}},
				"servers": []any{[]any{
					map[string]any{"type": "str", "packet": "HTTP/1.1 101 Switching Protocols\r\nX-Nonce: "},
					map[string]any{"reuse": "nonce"},
					map[string]any{"type": "str", "packet": "\r\n\r\n"},
				}},
			}}},
		},
		{
			name: "header-custom-transform",
			xray: map[string]any{"tcp": []any{map[string]any{"type": "header-custom", "settings": map[string]any{
				"clients": []any{[]any{
					map[string]any{"type": "hex", "packet": "16030100"},
					map[string]any{"rand": 2, "capture": "len"},
				}},
				"servers": []any{[]any{
					map[string]any{"type": "hex", "packet": "16030300"},
					map[string]any{"transform": map[string]any{"op": "slice", "args": []any{map[string]any{"reuse": "len"}, map[string]any{"u64": 0}, map[string]any{"u64": 1}}}},
				}},
			}}}},
			core: map[string]any{"tcp": []any{map[string]any{"type": "header-custom",
				"clients": []any{[]any{
					map[string]any{"type": "hex", "packet": "16030100"},
					map[string]any{"rand": 2, "capture": "len"},
				}},
				"servers": []any{[]any{
					map[string]any{"type": "hex", "packet": "16030300"},
					map[string]any{"transform": map[string]any{"op": "slice", "args": []any{map[string]any{"reuse": "len"}, map[string]any{"u64": 0}, map[string]any{"u64": 1}}}},
				}},
			}}},
		},
		{
			name: "sudoku-entropy",
			xray: map[string]any{"tcp": []any{map[string]any{"type": "sudoku", "settings": map[string]any{"password": "sudoku-pass", "paddingMin": 10, "paddingMax": 30}}}},
			core: map[string]any{"tcp": []any{map[string]any{"type": "sudoku", "password": "sudoku-pass", "padding-min": 10, "padding-max": 30}}},
		},
		{
			name: "sudoku-ascii",
			xray: map[string]any{"tcp": []any{map[string]any{"type": "sudoku", "settings": map[string]any{"password": "sudoku-pass", "ascii": "prefer_ascii"}}}},
			core: map[string]any{"tcp": []any{map[string]any{"type": "sudoku", "password": "sudoku-pass", "ascii": "prefer_ascii"}}},
		},
		{
			name: "sudoku-custom-tables",
			xray: map[string]any{"tcp": []any{map[string]any{"type": "sudoku", "settings": map[string]any{"password": "sudoku-pass", "customTables": []any{"xpxvvpvv", "vxpvxvvp"}, "paddingMin": 100, "paddingMax": 100}}}},
			core: map[string]any{"tcp": []any{map[string]any{"type": "sudoku", "password": "sudoku-pass", "custom-tables": []any{"xpxvvpvv", "vxpvxvvp"}, "padding-min": 100, "padding-max": 100}}},
		},
		{
			name: "xmc",
			xray: map[string]any{"tcp": []any{map[string]any{"type": "xmc", "settings": map[string]any{"password": "mc-pass", "hostname": "mc.example.com", "profiles": []any{xmcXray}}}}},
			core: map[string]any{"tcp": []any{map[string]any{"type": "xmc", "password": "mc-pass", "hostname": "mc.example.com", "profiles": []any{xmcCore}}}},
		},
		{
			// Several masks: the first is outermost, the last is on the wire.
			name: "chain-custom-sudoku-fragment",
			xray: map[string]any{"tcp": []any{
				map[string]any{"type": "header-custom", "settings": map[string]any{
					"clients": []any{[]any{map[string]any{"type": "str", "packet": "hello"}}},
					"servers": []any{[]any{map[string]any{"type": "str", "packet": "world"}}},
				}},
				map[string]any{"type": "sudoku", "settings": map[string]any{"password": "chain"}},
				map[string]any{"type": "fragment", "settings": map[string]any{"packets": "1-2", "length": "10-20"}},
			}},
			core: map[string]any{"tcp": []any{
				map[string]any{"type": "header-custom",
					"clients": []any{[]any{map[string]any{"type": "str", "packet": "hello"}}},
					"servers": []any{[]any{map[string]any{"type": "str", "packet": "world"}}},
				},
				map[string]any{"type": "sudoku", "password": "chain"},
				map[string]any{"type": "fragment", "packets": "1-2", "length": "10-20"},
			}},
		},
	}
}

func udpMaskPairs(xdnsPort int) []maskPair {
	return []maskPair{
		{
			name: "noise",
			xray: map[string]any{"udp": []any{map[string]any{"type": "noise", "settings": map[string]any{"reset": "30", "noise": []any{
				map[string]any{"type": "exp", "packet": "<b 0d0a0d0a> <t> <r 24>", "delay": "1-2"},
				map[string]any{"rand": "40-60"},
			}}}}},
			core: map[string]any{"udp": []any{map[string]any{"type": "noise", "reset": 30, "noise": []any{
				map[string]any{"type": "exp", "packet": "<b 0d0a0d0a> <t> <r 24>", "delay": "1-2"},
				map[string]any{"rand": "40-60"},
			}}}},
		},
		{
			name: "header-custom-prefix",
			xray: map[string]any{"udp": []any{map[string]any{"type": "header-custom", "settings": map[string]any{
				"client": []any{map[string]any{"type": "hex", "packet": "c0"}, map[string]any{"rand": 3}},
				"server": []any{map[string]any{"type": "hex", "packet": "c1"}, map[string]any{"rand": 1}},
			}}}},
			core: map[string]any{"udp": []any{map[string]any{"type": "header-custom",
				"client": []any{map[string]any{"type": "hex", "packet": "c0"}, map[string]any{"rand": 3}},
				"server": []any{map[string]any{"type": "hex", "packet": "c1"}, map[string]any{"rand": 1}},
			}}},
		},
		{
			name: "header-custom-standalone",
			xray: map[string]any{"udp": []any{map[string]any{"type": "header-custom", "settings": map[string]any{
				"mode":   "standalone",
				"client": []any{map[string]any{"type": "hex", "packet": "000100002112a442"}, map[string]any{"rand": 12, "capture": "txid"}},
				"server": []any{map[string]any{"type": "hex", "packet": "010100002112a442"}, map[string]any{"reuse": "txid"}},
			}}}},
			core: map[string]any{"udp": []any{map[string]any{"type": "header-custom",
				"mode":   "standalone",
				"client": []any{map[string]any{"type": "hex", "packet": "000100002112a442"}, map[string]any{"rand": 12, "capture": "txid"}},
				"server": []any{map[string]any{"type": "hex", "packet": "010100002112a442"}, map[string]any{"reuse": "txid"}},
			}}},
		},
		{
			name: "sudoku",
			xray: map[string]any{"udp": []any{map[string]any{"type": "sudoku", "settings": map[string]any{"password": "sudoku-udp", "ascii": "prefer_ascii"}}}},
			core: map[string]any{"udp": []any{map[string]any{"type": "sudoku", "password": "sudoku-udp", "ascii": "prefer_ascii"}}},
		},
		{
			// Server side needs nothing; the client changes its socket.
			name: "udphop-local",
			xray: map[string]any{},
			core: map[string]any{"udp": []any{map[string]any{"type": "udphop", "mode": "intervalLocal", "interval": "5"}}},
		},
		{
			name: "xdns",
			xray: map[string]any{"udp": []any{map[string]any{"type": "xdns", "settings": map[string]any{
				"domains": []any{map[string]any{"names": []any{"t.example.com"}, "edns0": 4096}},
			}}}},
			core: map[string]any{"udp": []any{map[string]any{"type": "xdns",
				"domains":   []any{map[string]any{"names": []any{"t.example.com"}, "edns0": 4096, "types": []any{16}}},
				"resolvers": []any{map[string]any{"addrs": []any{fmt.Sprintf("udp://127.0.0.1:%d", xdnsPort)}}},
			}}},
		},
		{
			name: "chain-noise-custom-sudoku",
			xray: map[string]any{"udp": []any{
				map[string]any{"type": "noise", "settings": map[string]any{"noise": []any{map[string]any{"rand": "16-32"}}}},
				map[string]any{"type": "header-custom", "settings": map[string]any{
					"client": []any{map[string]any{"type": "hex", "packet": "01"}},
					"server": []any{map[string]any{"type": "hex", "packet": "02"}},
				}},
				map[string]any{"type": "sudoku", "settings": map[string]any{"password": "chain"}},
			}},
			core: map[string]any{"udp": []any{
				map[string]any{"type": "noise", "noise": []any{map[string]any{"rand": "16-32"}}},
				map[string]any{"type": "header-custom",
					"client": []any{map[string]any{"type": "hex", "packet": "01"}},
					"server": []any{map[string]any{"type": "hex", "packet": "02"}},
				},
				map[string]any{"type": "sudoku", "password": "chain"},
			}},
		},
	}
}

func tlsStream(certFile, keyFile string, alpn []string) map[string]any {
	settings := map[string]any{
		"certificates": []any{map[string]any{"certificateFile": certFile, "keyFile": keyFile}},
	}
	if alpn != nil {
		settings["alpn"] = alpn
	}
	return map[string]any{"security": "tls", "tlsSettings": settings}
}

func TestXrayFinalMaskTCP(t *testing.T) {
	bin := xrayBinary(t)
	echoPort := echoServer(t)
	certFile, keyFile := writeCert(t, t.TempDir())

	type transport struct {
		name   string
		xray   map[string]any // network part of streamSettings
		core   map[string]any // network part of the proxy
		tls    bool
		protos []string // vless, trojan
	}
	transports := []transport{
		{name: "vless-tcp", xray: map[string]any{"network": "tcp"}, core: map[string]any{}, protos: []string{"vless"}},
		{name: "vless-tcp-tls", xray: map[string]any{"network": "tcp"}, core: map[string]any{}, tls: true, protos: []string{"vless"}},
		{name: "trojan-tcp-tls", xray: map[string]any{"network": "tcp"}, core: map[string]any{}, tls: true, protos: []string{"trojan"}},
		{name: "vless-ws-tls", xray: map[string]any{"network": "ws", "wsSettings": map[string]any{"path": "/ws"}}, core: map[string]any{"network": "ws", "ws-opts": map[string]any{"path": "/ws"}}, tls: true, protos: []string{"vless"}},
		{name: "vless-grpc-tls", xray: map[string]any{"network": "grpc", "grpcSettings": map[string]any{"serviceName": "svc"}}, core: map[string]any{"network": "grpc", "grpc-opts": map[string]any{"grpc-service-name": "svc"}}, tls: true, protos: []string{"vless"}},
		{name: "vless-xhttp-h2-tls", xray: map[string]any{"network": "xhttp", "xhttpSettings": map[string]any{"path": "/x"}}, core: map[string]any{"network": "xhttp", "xhttp-opts": map[string]any{"path": "/x"}}, tls: true, protos: []string{"vless"}},
	}
	// Every mask over plain vless TCP and TLS; the other transports with a
	// chain, to check where the masks are applied.
	for _, tr := range transports {
		pairs := tcpMaskPairs()
		if tr.name != "vless-tcp" && tr.name != "vless-tcp-tls" {
			pairs = pairs[len(pairs)-1:]
		}
		for _, proto := range tr.protos {
			for _, pair := range pairs {
				tr, pair, proto := tr, pair, proto
				t.Run(tr.name+"/"+pair.name, func(t *testing.T) {
					stream := map[string]any{"finalmask": pair.xray}
					for k, v := range tr.xray {
						stream[k] = v
					}
					if tr.tls {
						for k, v := range tlsStream(certFile, keyFile, nil) {
							stream[k] = v
						}
					}
					port := freePort(t, "tcp")
					startXray(t, bin, xrayServer{proto: proto, stream: stream, port: port, readyTCP: freePort(t, "tcp")})

					core := map[string]any{
						"name": tr.name, "type": proto, "server": "127.0.0.1", "port": port,
						"skip-cert-verify": true, "finalmask": pair.core,
					}
					switch proto {
					case "vless":
						core["uuid"] = xrayUUID
						core["tls"] = tr.tls
						core["servername"] = "localhost"
					case "trojan":
						core["password"] = xrayPassword
						core["sni"] = "localhost"
					}
					for k, v := range tr.core {
						core[k] = v
					}
					proxy, err := ParseProxy(core)
					if err != nil {
						t.Fatal(err)
					}
					defer proxy.Close()
					echoThrough(t, proxy, echoPort, 256*1024)
				})
			}
		}
	}
}

func TestXrayFinalMaskUDP(t *testing.T) {
	bin := xrayBinary(t)
	echoPort := echoServer(t)
	certFile, keyFile := writeCert(t, t.TempDir())

	port := freePort(t, "udp")
	for _, pair := range udpMaskPairs(port) {
		pair := pair
		t.Run(pair.name, func(t *testing.T) {
			stream := map[string]any{
				"network":       "xhttp",
				"xhttpSettings": map[string]any{"path": "/x"},
				"finalmask":     pair.xray,
			}
			for k, v := range tlsStream(certFile, keyFile, []string{"h3"}) {
				stream[k] = v
			}
			startXray(t, bin, xrayServer{proto: "vless", stream: stream, port: port, network: "udp", readyTCP: freePort(t, "tcp")})

			proxy, err := ParseProxy(map[string]any{
				"name": "vless-h3", "type": "vless", "server": "127.0.0.1", "port": port, "uuid": xrayUUID,
				"network": "xhttp", "xhttp-opts": map[string]any{"path": "/x"},
				"tls": true, "alpn": []any{"h3"}, "servername": "localhost", "skip-cert-verify": true,
				"finalmask": pair.core,
			})
			if err != nil {
				t.Fatal(err)
			}
			defer proxy.Close()
			echoThrough(t, proxy, echoPort, 64*1024)
		})
	}
}

// A mask on one side only must break the connection: it is how the tests
// above prove the masks are applied, not skipped by both sides.
func TestXrayFinalMaskMismatch(t *testing.T) {
	bin := xrayBinary(t)
	echoPort := echoServer(t)
	for _, c := range []struct {
		name string
		xray map[string]any
		core map[string]any
	}{
		{"server-sudoku", map[string]any{"tcp": []any{map[string]any{"type": "sudoku", "settings": map[string]any{"password": "p"}}}}, map[string]any{}},
		{"client-sudoku", map[string]any{}, map[string]any{"tcp": []any{map[string]any{"type": "sudoku", "password": "p"}}}},
		{"sudoku-passwords", map[string]any{"tcp": []any{map[string]any{"type": "sudoku", "settings": map[string]any{"password": "p"}}}}, map[string]any{"tcp": []any{map[string]any{"type": "sudoku", "password": "q"}}}},
		{"header-custom-sequence", map[string]any{"tcp": []any{map[string]any{"type": "header-custom", "settings": map[string]any{
			"clients": []any{[]any{map[string]any{"type": "str", "packet": "hello"}}},
			"servers": []any{[]any{map[string]any{"type": "str", "packet": "world"}}},
		}}}}, map[string]any{"tcp": []any{map[string]any{"type": "header-custom",
			"clients": []any{[]any{map[string]any{"type": "str", "packet": "hello"}}},
			"servers": []any{[]any{map[string]any{"type": "str", "packet": "there"}}},
		}}}},
	} {
		c := c
		t.Run(c.name, func(t *testing.T) {
			port := freePort(t, "tcp")
			startXray(t, bin, xrayServer{proto: "vless", stream: map[string]any{"network": "tcp", "finalmask": c.xray}, port: port, readyTCP: freePort(t, "tcp")})
			proxy, err := ParseProxy(map[string]any{
				"name": c.name, "type": "vless", "server": "127.0.0.1", "port": port, "uuid": xrayUUID, "finalmask": c.core,
			})
			if err != nil {
				t.Fatal(err)
			}
			defer proxy.Close()
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
				t.Fatal("the echo came through a mismatched mask")
			}
		})
	}
}

// countingDialer records the UDP sockets a proxy opens, to see udphop hop.
type countingDialer struct {
	C.Dialer
	mu    sync.Mutex
	udp   []string
	ports map[string]bool
}

func newCountingDialer() *countingDialer {
	return &countingDialer{Dialer: dialer.NewDialer(), ports: map[string]bool{}}
}

func (d *countingDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	conn, err := d.Dialer.DialContext(ctx, network, address)
	if err == nil && strings.HasPrefix(network, "udp") {
		d.mu.Lock()
		d.udp = append(d.udp, conn.LocalAddr().String())
		_, port, _ := net.SplitHostPort(address)
		d.ports[port] = true
		d.mu.Unlock()
	}
	return conn, err
}

func (d *countingDialer) stats() (int, int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.udp), len(d.ports)
}

// udpRelay forwards datagrams from one port to target, one socket per
// client, as a DNAT rule on a server would for udphop's remote ports.
func udpRelay(t *testing.T, listen, target int) {
	t.Helper()
	ln, err := net.ListenPacket("udp", fmt.Sprintf("127.0.0.1:%d", listen))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	targetAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: target}
	go func() {
		var mu sync.Mutex
		upstreams := map[string]*net.UDPConn{}
		buf := make([]byte, 65535)
		for {
			n, from, err := ln.ReadFrom(buf)
			if err != nil {
				return
			}
			mu.Lock()
			up := upstreams[from.String()]
			if up == nil {
				up, err = net.DialUDP("udp", nil, targetAddr)
				if err != nil {
					mu.Unlock()
					continue
				}
				upstreams[from.String()] = up
				go func(up *net.UDPConn, client net.Addr) {
					b := make([]byte, 65535)
					for {
						n, err := up.Read(b)
						if err != nil {
							return
						}
						_, _ = ln.WriteTo(b[:n], client)
					}
				}(up, from)
			}
			mu.Unlock()
			_, _ = up.Write(buf[:n])
		}
	}()
}

// echoOnce sends one payload through an open connection and reads it back.
func echoOnce(t *testing.T, conn net.Conn, size int) {
	t.Helper()
	payload := make([]byte, size)
	_, _ = rand.Read(payload)
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	go func() { _, _ = conn.Write(payload) }()
	got := make([]byte, size)
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(payload, got) {
		t.Fatal("echo differs")
	}
}

// TestXrayFinalMaskUDPHopLive keeps one QUIC connection open across hops:
// the client changes its socket (and its remote port, through relays that
// stand in for the server's DNAT) every 5 seconds while data flows.
func TestXrayFinalMaskUDPHopLive(t *testing.T) {
	bin := xrayBinary(t)
	echoPort := echoServer(t)
	certFile, keyFile := writeCert(t, t.TempDir())

	for _, mode := range []string{"intervalLocal", "intervalLocal,intervalRemote"} {
		mode := mode
		t.Run(mode, func(t *testing.T) {
			port := freePort(t, "udp")
			stream := map[string]any{"network": "xhttp", "xhttpSettings": map[string]any{"path": "/x"}}
			for k, v := range tlsStream(certFile, keyFile, []string{"h3"}) {
				stream[k] = v
			}
			startXray(t, bin, xrayServer{proto: "vless", stream: stream, port: port, network: "udp", readyTCP: freePort(t, "tcp")})

			hop := map[string]any{"type": "udphop", "mode": mode, "interval": "5"}
			if strings.Contains(mode, "Remote") {
				ports := []int{port}
				for i := 0; i < 3; i++ {
					p := freePort(t, "udp")
					udpRelay(t, p, port)
					ports = append(ports, p)
				}
				var list []any
				for _, p := range ports {
					list = append(list, fmt.Sprint(p))
				}
				hop["remote-ports"] = list
			}
			counting := newCountingDialer()
			proxy, err := ParseProxy(map[string]any{
				"name": "vless-h3-hop", "type": "vless", "server": "127.0.0.1", "port": port, "uuid": xrayUUID,
				"network": "xhttp", "xhttp-opts": map[string]any{"path": "/x"},
				"tls": true, "alpn": []any{"h3"}, "servername": "localhost", "skip-cert-verify": true,
				"finalmask": map[string]any{"udp": []any{hop}},
			}, WithDialerForAPI(counting))
			if err != nil {
				t.Fatal(err)
			}
			defer proxy.Close()

			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			conn, err := proxy.DialContext(ctx, &C.Metadata{NetWork: C.TCP, DstIP: netip.MustParseAddr("127.0.0.1"), DstPort: uint16(echoPort)})
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			// Three echoes 6 s apart span at least two hops of 5 s.
			for i := 0; i < 3; i++ {
				if i > 0 {
					time.Sleep(6 * time.Second)
				}
				echoOnce(t, conn, 32*1024)
			}
			sockets, ports := counting.stats()
			t.Logf("udp sockets opened: %d, distinct remote ports: %d", sockets, ports)
			if sockets < 3 {
				t.Fatalf("expected at least 3 UDP sockets (initial and two hops), got %d", sockets)
			}
			if strings.Contains(mode, "Remote") && ports < 2 {
				t.Fatalf("expected the remote port to change, saw %d distinct ports", ports)
			}
		})
	}
}

// realityOrigin is the TLS server REALITY shows to clients it does not know.
func realityOrigin(t *testing.T, certFile, keyFile string) string {
	t.Helper()
	cert, err := stdtls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := stdtls.Listen("tcp", "127.0.0.1:0", &stdtls.Config{Certificates: []stdtls.Certificate{cert}, NextProtos: []string{"h2", "http/1.1"}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = io.Copy(io.Discard, c)
			}()
		}
	}()
	return ln.Addr().String()
}

// TestXrayFinalMaskReality runs the fork as a REALITY server with the mask
// chain and Prizrak-Core as the REALITY client with the same chain, over
// vless tcp with and without Vision and over trojan.
func TestXrayFinalMaskReality(t *testing.T) {
	bin := xrayBinary(t)
	echoPort := echoServer(t)
	certFile, keyFile := writeCert(t, t.TempDir())
	origin := realityOrigin(t, certFile, keyFile)
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	const shortID = "0123456789abcdef"
	pairs := tcpMaskPairs()
	chain := pairs[len(pairs)-1]

	for _, c := range []struct {
		name, proto, flow string
		pair              maskPair
	}{
		{"vless", "vless", "", chain},
		{"vless-vision-nomask", "vless", "xtls-rprx-vision", pairs[0]},
		{"vless-vision-fragment", "vless", "xtls-rprx-vision", pairs[1]},
		{"vless-vision-custom", "vless", "xtls-rprx-vision", pairs[3]},
		{"vless-vision-sudoku", "vless", "xtls-rprx-vision", pairs[5]},
		{"vless-vision", "vless", "xtls-rprx-vision", chain},
		{"vless-xmc", "vless", "", pairs[len(pairs)-2]},
		{"trojan", "trojan", "", chain},
	} {
		c := c
		t.Run(c.name, func(t *testing.T) {
			stream := map[string]any{
				"network":  "tcp",
				"security": "reality",
				"realitySettings": map[string]any{
					"target":      origin,
					"serverNames": []any{"localhost"},
					"privateKey":  base64.RawURLEncoding.EncodeToString(privateKey.Bytes()),
					"shortIds":    []any{shortID},
				},
				"finalmask": c.pair.xray,
			}
			port := freePort(t, "tcp")
			startXray(t, bin, xrayServer{proto: c.proto, stream: stream, port: port, readyTCP: freePort(t, "tcp")})

			core := map[string]any{
				"name": c.name, "type": c.proto, "server": "127.0.0.1", "port": port,
				"client-fingerprint": "chrome",
				"reality-opts":       map[string]any{"public-key": base64.RawURLEncoding.EncodeToString(privateKey.PublicKey().Bytes()), "short-id": shortID},
				"finalmask":          c.pair.core,
			}
			switch c.proto {
			case "vless":
				core["uuid"] = xrayUUID
				if c.flow != "" {
					core["uuid"] = xrayVisionUUID
				}
				core["tls"] = true
				core["servername"] = "localhost"
				core["flow"] = c.flow
			case "trojan":
				core["password"] = xrayPassword
				core["sni"] = "localhost"
			}
			proxy, err := ParseProxy(core)
			if err != nil {
				t.Fatal(err)
			}
			defer proxy.Close()
			echoThrough(t, proxy, echoPort, 256*1024)
		})
	}

	// A chain that differs must fail against the REALITY server too.
	t.Run("mismatch", func(t *testing.T) {
		stream := map[string]any{
			"network": "tcp", "security": "reality",
			"realitySettings": map[string]any{
				"target": origin, "serverNames": []any{"localhost"},
				"privateKey": base64.RawURLEncoding.EncodeToString(privateKey.Bytes()), "shortIds": []any{shortID},
			},
			"finalmask": chain.xray,
		}
		port := freePort(t, "tcp")
		startXray(t, bin, xrayServer{proto: "vless", stream: stream, port: port, readyTCP: freePort(t, "tcp")})
		proxy, err := ParseProxy(map[string]any{
			"name": "bad", "type": "vless", "server": "127.0.0.1", "port": port, "uuid": xrayUUID,
			"tls": true, "servername": "localhost", "client-fingerprint": "chrome",
			"reality-opts": map[string]any{"public-key": base64.RawURLEncoding.EncodeToString(privateKey.PublicKey().Bytes()), "short-id": shortID},
			"finalmask":    map[string]any{"tcp": []any{map[string]any{"type": "sudoku", "password": "other"}}},
		})
		if err != nil {
			t.Fatal(err)
		}
		defer proxy.Close()
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
			t.Fatal("the echo came through a mismatched mask")
		}
	})
}
