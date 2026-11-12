package adapter

import (
	"crypto/sha256"
	stdtls "crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	stdhttp "net/http"
	"net/http/httptest"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/http"
	"github.com/metacubex/quic-go/http3"
	"github.com/metacubex/tls"
)

// The xdns client of Prizrak-Core against Xray-core as the xdns server, with
// the resolvers of XTLS/Xray-core 10879a4a (DoH) and 14df0738 (DNS over TCP
// with workers) between them: each is a server in the test that passes the
// queries to Xray's UDP port, as a public resolver would.
//
//	XRAY_BIN=/path/to/xray go test ./adapter/ -run TestXrayXDNSResolvers -v

// resolverStats counts what a test resolver saw.
type resolverStats struct {
	queries   atomic.Int32
	conns     atomic.Int32
	userAgent atomic.Int32 // requests with a User-Agent
	mu        sync.Mutex
	snis      map[string]bool
	protos    map[int]bool
}

func newResolverStats() *resolverStats {
	return &resolverStats{snis: map[string]bool{}, protos: map[int]bool{}}
}

func (s *resolverStats) request(proto int, userAgents int) {
	s.queries.Add(1)
	if userAgents > 0 {
		s.userAgent.Add(1)
	}
	s.mu.Lock()
	s.protos[proto] = true
	s.mu.Unlock()
}

func (s *resolverStats) hello(sni string) {
	s.conns.Add(1)
	s.mu.Lock()
	s.snis[sni] = true
	s.mu.Unlock()
}

// forwardUDP asks the xdns server at addr, as a recursive resolver does.
func forwardUDP(addr string, query []byte) ([]byte, error) {
	conn, err := net.Dial("udp", addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write(query); err != nil {
		return nil, err
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

// startDoHRelay serves DoH over HTTP/2 (Go's net/http) or HTTP/3 (quic-go)
// with the certificate, passing each query to the xdns server.
func startDoHRelay(t *testing.T, certFile, keyFile string, h3 bool, xdnsServer string, stats *resolverStats) string {
	t.Helper()
	if h3 {
		pair, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			t.Fatal(err)
		}
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		srv := &http3.Server{
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				query, _ := io.ReadAll(r.Body)
				stats.request(r.ProtoMajor, len(r.Header.Values("User-Agent")))
				answer, err := forwardUDP(xdnsServer, query)
				if err != nil {
					w.WriteHeader(http.StatusBadGateway)
					return
				}
				w.Header().Set("Content-Type", "application/dns-message")
				_, _ = w.Write(answer)
			}),
			TLSConfig: http3.ConfigureTLSConfig(&tls.Config{
				Certificates: []tls.Certificate{pair},
				GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
					stats.hello(hello.ServerName)
					return nil, nil
				},
			}),
		}
		go func() { _ = srv.Serve(pc) }()
		t.Cleanup(func() {
			_ = srv.Close()
			_ = pc.Close()
		})
		return "https://" + pc.LocalAddr().String() + "/dns-query"
	}
	pair, err := stdtls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		query, _ := io.ReadAll(r.Body)
		stats.request(r.ProtoMajor, len(r.Header.Values("User-Agent")))
		answer, err := forwardUDP(xdnsServer, query)
		if err != nil {
			w.WriteHeader(stdhttp.StatusBadGateway)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(answer)
	}))
	srv.EnableHTTP2 = true
	srv.TLS = &stdtls.Config{
		Certificates: []stdtls.Certificate{pair},
		GetConfigForClient: func(hello *stdtls.ClientHelloInfo) (*stdtls.Config, error) {
			stats.hello(hello.ServerName)
			return nil, nil
		},
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv.URL + "/dns-query"
}

// startTCPDNSRelay serves DNS over TCP, passing each query to the xdns
// server; it counts the connections the workers open.
func startTCPDNSRelay(t *testing.T, xdnsServer string, stats *resolverStats) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			stats.conns.Add(1)
			go func() {
				defer conn.Close()
				buf := make([]byte, 2+4096)
				for {
					if _, err := io.ReadFull(conn, buf[:2]); err != nil {
						return
					}
					n := int(binary.BigEndian.Uint16(buf[:2]))
					if _, err := io.ReadFull(conn, buf[2:2+n]); err != nil {
						return
					}
					stats.request(0, 0)
					answer, err := forwardUDP(xdnsServer, buf[2:2+n])
					if err != nil {
						return
					}
					frame := make([]byte, 2+len(answer))
					binary.BigEndian.PutUint16(frame, uint16(len(answer)))
					copy(frame[2:], answer)
					if _, err := conn.Write(frame); err != nil {
						return
					}
				}
			}()
		}
	}()
	return "tcp://" + ln.Addr().String()
}

func certPin(t *testing.T, certFile string) string {
	t.Helper()
	data, err := os.ReadFile(certFile)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(data)
	sum := sha256.Sum256(block.Bytes)
	return hex.EncodeToString(sum[:])
}

func TestXrayXDNSResolvers(t *testing.T) {
	bin := xrayBinary(t)
	echoPort := echoServer(t)
	certFile, keyFile := writeCert(t, t.TempDir())
	pin := certPin(t, certFile)

	type resolverCase struct {
		name     string
		resolver func(t *testing.T, xdnsServer string, stats *resolverStats) map[string]any
		proto    int // the HTTP version the DoH server must see, 0 for tcp
		worker   int
	}
	resolvers := []resolverCase{
		{name: "doh-h2", proto: 2, worker: 8, resolver: func(t *testing.T, xdnsServer string, stats *resolverStats) map[string]any {
			return map[string]any{
				"addrs":  []any{startDoHRelay(t, certFile, keyFile, false, xdnsServer, stats)},
				"worker": 8,
				// The SNI fronts; the request still names 127.0.0.1.
				"tls-config": map[string]any{"server-name": "front.example", "pinned-peer-cert-sha256": pin},
			}
		}},
		{name: "doh-h3", proto: 3, worker: 8, resolver: func(t *testing.T, xdnsServer string, stats *resolverStats) map[string]any {
			return map[string]any{
				"addrs":       []any{startDoHRelay(t, certFile, keyFile, true, xdnsServer, stats)},
				"worker":      8,
				"tls-config":  map[string]any{"server-name": "front.example", "pinned-peer-cert-sha256": pin, "alpn": []any{"h3"}},
				"quic-config": map[string]any{"congestion": "bbr", "max-idle-timeout": 30},
			}
		}},
		{name: "tcp-worker", worker: 4, resolver: func(t *testing.T, xdnsServer string, stats *resolverStats) map[string]any {
			return map[string]any{"addrs": []any{startTCPDNSRelay(t, xdnsServer, stats)}, "worker": 4}
		}},
	}
	transports := []string{"mkcp", "xhttp-h3"}
	for _, transport := range transports {
		for _, rc := range resolvers {
			transport, rc := transport, rc
			t.Run(transport+"/"+rc.name, func(t *testing.T) {
				port := freePort(t, "udp")
				xdnsServer := fmt.Sprintf("127.0.0.1:%d", port)
				serverMask := map[string]any{"udp": []any{map[string]any{"type": "xdns", "settings": map[string]any{
					"domains": []any{map[string]any{"names": []any{"t.example.com"}, "edns0": 4096}},
				}}}}
				stats := newResolverStats()
				clientMask := map[string]any{"udp": []any{map[string]any{"type": "xdns",
					"domains":   []any{map[string]any{"names": []any{"t.example.com"}, "edns0": 4096, "types": []any{16}}},
					"resolvers": []any{rc.resolver(t, xdnsServer, stats)},
				}}}
				var proxyConfig map[string]any
				size := 8 * 1024
				switch transport {
				case "mkcp":
					startXray(t, bin, xrayServer{proto: "vless", stream: mkcpStream(77, serverMask), port: port, network: "udp", readyTCP: freePort(t, "tcp")})
					proxyConfig = mkcpProxy(port, 77, clientMask)
				case "xhttp-h3":
					stream := map[string]any{"network": "xhttp", "xhttpSettings": map[string]any{"path": "/x"}, "finalmask": serverMask}
					for k, v := range tlsStream(certFile, keyFile, []string{"h3"}) {
						stream[k] = v
					}
					startXray(t, bin, xrayServer{proto: "vless", stream: stream, port: port, network: "udp", readyTCP: freePort(t, "tcp")})
					proxyConfig = map[string]any{
						"name": "vless-h3", "type": "vless", "server": "127.0.0.1", "port": port, "uuid": xrayUUID,
						"network": "xhttp", "xhttp-opts": map[string]any{"path": "/x"},
						"tls": true, "alpn": []any{"h3"}, "servername": "localhost", "skip-cert-verify": true,
						"finalmask": clientMask,
					}
					size = 32 * 1024
				}
				proxy, err := ParseProxy(proxyConfig)
				if err != nil {
					t.Fatal(err)
				}
				start := time.Now()
				echoThrough(t, proxy, echoPort, size)
				echoed := time.Since(start)
				start = time.Now()
				_ = proxy.Close()
				closed := time.Since(start)
				t.Logf("%s: 2x%d bytes echoed in %v, %d queries, %d connections to the resolver, closed in %v", rc.name, size, echoed.Round(time.Millisecond), stats.queries.Load(), stats.conns.Load(), closed.Round(time.Millisecond))
				if closed > 3*time.Second {
					t.Fatalf("the proxy took %v to close", closed)
				}

				if stats.queries.Load() == 0 {
					t.Fatal("no query reached the resolver")
				}
				if n := stats.userAgent.Load(); n > 0 {
					t.Fatalf("%d requests carried a User-Agent", n)
				}
				// echoThrough makes two connections, so two xdns clients may
				// run: a tcp resolver opens up to worker connections for each,
				// a DoH one a connection for each.
				if n := stats.conns.Load(); rc.proto == 0 && n > int32(2*rc.worker) {
					t.Fatalf("%d connections to a tcp resolver with %d workers", n, rc.worker)
				}
				if n := stats.conns.Load(); rc.proto != 0 && n > 4 {
					t.Fatalf("%d TLS connections to a DoH resolver", n)
				}
				stats.mu.Lock()
				defer stats.mu.Unlock()
				if rc.proto != 0 {
					if len(stats.protos) != 1 || !stats.protos[rc.proto] {
						t.Fatalf("HTTP versions %v, want %d", stats.protos, rc.proto)
					}
					if len(stats.snis) != 1 || !stats.snis["front.example"] {
						t.Fatalf("SNIs %v, want front.example", stats.snis)
					}
				}
			})
		}
	}
}
