package xdns

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	stdtls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	stdhttp "net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/transport/finalmask"

	"github.com/metacubex/http"
	"github.com/metacubex/http/httptrace"
	"github.com/metacubex/quic-go/http3"
	"github.com/metacubex/tls"
	"github.com/stretchr/testify/require"
)

// testCert is a certificate for dns.example and 127.0.0.1, signed by a CA of
// its own.
type testCert struct {
	caDER, leafDER []byte
	certPEM        []byte
	keyPEM         []byte
	caPool         *x509.CertPool
}

func newTestCert(t *testing.T) *testCert {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "xdns test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	ca, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "dns.example"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"dns.example"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, ca, &key.PublicKey, caKey)
	require.NoError(t, err)
	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	certPEM := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})...)
	return &testCert{
		caDER:   caDER,
		leafDER: leafDER,
		certPEM: certPEM,
		keyPEM:  pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
		caPool:  pool,
	}
}

func pinOf(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

func TestVerifyPeer(t *testing.T) {
	cert := newTestCert(t)
	chain := [][]byte{cert.leafDER, cert.caDER}
	now := time.Now()
	build := func(o TLSOption) *TLSConfig {
		c, err := o.Build()
		require.NoError(t, err)
		return c
	}
	empty := x509.NewCertPool()

	// A pinned leaf passes whatever the name.
	c := build(TLSOption{PinnedPeerCertSha256: stringList{pinOf(cert.leafDER)}})
	require.NoError(t, c.verifyPeer(chain, empty, "front.example", now))
	// A pinned CA verifies the leaf for the server name.
	c = build(TLSOption{PinnedPeerCertSha256: stringList{pinOf(cert.caDER)}})
	require.NoError(t, c.verifyPeer(chain, empty, "dns.example", now))
	require.Error(t, c.verifyPeer(chain, empty, "front.example", now))
	// ...or for the names to verify by, which fronting needs.
	c = build(TLSOption{PinnedPeerCertSha256: stringList{pinOf(cert.caDER)}, VerifyPeerCertByName: stringList{"other.example,dns.example"}})
	require.NoError(t, c.verifyPeer(chain, empty, "front.example", now))
	// Names alone verify against the roots.
	c = build(TLSOption{VerifyPeerCertByName: stringList{"dns.example"}})
	require.NoError(t, c.verifyPeer(chain, cert.caPool, "front.example", now))
	require.Error(t, c.verifyPeer(chain, empty, "front.example", now))
	c = build(TLSOption{VerifyPeerCertByName: stringList{"other.example"}})
	require.Error(t, c.verifyPeer(chain, cert.caPool, "dns.example", now))
	// A pin of nothing in the chain fails.
	c = build(TLSOption{PinnedPeerCertSha256: stringList{strings.Repeat("00", 32)}})
	require.Error(t, c.verifyPeer(chain, cert.caPool, "dns.example", now))
}

// dnsTCPServer answers DNS over TCP with the query itself, each answer after
// a value on release when hold is set; it counts the connections.
type dnsTCPServer struct {
	addr     string
	hold     bool
	release  chan struct{}
	accepted atomic.Int32
	pending  atomic.Int32
	most     atomic.Int32
	queries  atomic.Int32
	closeOne bool // close the connection after each answer
}

func startDNSTCPServer(t *testing.T, s *dnsTCPServer) *dnsTCPServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })
	s.addr = ln.Addr().String()
	if s.release == nil {
		s.release = make(chan struct{}, 1024)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			s.accepted.Add(1)
			go func() {
				defer conn.Close()
				buf := make([]byte, 2+maxMessage)
				for {
					// Each query must come whole, length first (RFC 7766 8).
					if _, err := io.ReadFull(conn, buf[:2]); err != nil {
						return
					}
					n := int(binary.BigEndian.Uint16(buf[:2]))
					if _, err := io.ReadFull(conn, buf[2:2+n]); err != nil {
						return
					}
					s.queries.Add(1)
					pending := s.pending.Add(1)
					for {
						most := s.most.Load()
						if pending <= most || s.most.CompareAndSwap(most, pending) {
							break
						}
					}
					if s.hold {
						<-s.release
					}
					s.pending.Add(-1)
					if _, err := conn.Write(buf[:2+n]); err != nil {
						return
					}
					if s.closeOne {
						return
					}
				}
			}()
		}
	}()
	return s
}

func readAnswer(t *testing.T, r Resolver) []byte {
	t.Helper()
	ch := make(chan []byte, 1)
	go func() {
		buf := make([]byte, maxMessage)
		n, err := r.Read(buf)
		if err != nil {
			ch <- nil
			return
		}
		ch <- buf[:n]
	}()
	select {
	case p := <-ch:
		require.NotNil(t, p, "resolver closed")
		return p
	case <-time.After(5 * time.Second):
		t.Fatal("no answer")
		return nil
	}
}

// The tcp resolver of 14df0738: up to worker queries in flight, each on a
// connection of its own, dialed when needed and kept for the next query.
func TestTCPResolverWorkers(t *testing.T) {
	server := startDNSTCPServer(t, &dnsTCPServer{hold: true})
	r, err := NewTCPResolver(context.Background(), ResolverConfig{Type: "tcp", Addr: server.addr, Worker: 3}, localDialer())
	require.NoError(t, err)
	defer r.Close()
	require.Equal(t, int32(0), server.accepted.Load(), "dialed before the first query")

	sent := make(chan struct{}, 8)
	for i := 0; i < 5; i++ {
		i := i
		go func() {
			r.Send([]byte{byte(i), 1, 2, 3})
			sent <- struct{}{}
		}()
	}
	// Three workers take three queries; the other two Sends wait.
	for i := 0; i < 3; i++ {
		select {
		case <-sent:
		case <-time.After(5 * time.Second):
			t.Fatal("a worker did not take a query")
		}
	}
	select {
	case <-sent:
		t.Fatal("a fourth query was taken while three are in flight")
	case <-time.After(300 * time.Millisecond):
	}
	require.Eventually(t, func() bool { return server.pending.Load() == 3 }, 5*time.Second, 10*time.Millisecond)
	require.Equal(t, int32(3), server.accepted.Load())

	got := map[byte]bool{}
	for i := 0; i < 5; i++ {
		server.release <- struct{}{}
		answer := readAnswer(t, r)
		require.Len(t, answer, 4)
		require.Equal(t, []byte{1, 2, 3}, answer[1:])
		got[answer[0]] = true
	}
	require.Len(t, got, 5)
	require.Equal(t, int32(3), server.most.Load())

	// The connections stay for the next queries.
	for i := 0; i < 6; i++ {
		server.release <- struct{}{}
		r.Send([]byte{9, byte(i)})
		readAnswer(t, r)
	}
	require.Equal(t, int32(3), server.accepted.Load())
	require.Equal(t, "127.0.0.1", r.Addr().IP.String())
}

// A connection the server closed fails the query sent on it, as in Xray
// (the tunnel sends it again); the next query dials again.
func TestTCPResolverRedials(t *testing.T) {
	server := startDNSTCPServer(t, &dnsTCPServer{closeOne: true})
	r, err := NewTCPResolver(context.Background(), ResolverConfig{Type: "tcp", Addr: server.addr, Worker: 1}, localDialer())
	require.NoError(t, err)
	defer r.Close()
	answers := make(chan []byte, 16)
	go func() {
		for {
			buf := make([]byte, maxMessage)
			n, err := r.Read(buf)
			if err != nil {
				close(answers)
				return
			}
			answers <- buf[:n]
		}
	}()
	for i := 0; i < 4; i++ {
		answered := false
		for try := 0; try < 3 && !answered; try++ {
			r.Send([]byte{byte(i), 7})
			select {
			case answer := <-answers:
				require.Equal(t, []byte{byte(i), 7}, answer)
				answered = true
			case <-time.After(500 * time.Millisecond):
			}
		}
		require.True(t, answered, "query %d", i)
	}
	require.GreaterOrEqual(t, server.accepted.Load(), int32(4))
}

// Close ends workers that wait on answers that never come, and a dial to a
// resolver that is down is no error until a query needs it.
func TestTCPResolverClose(t *testing.T) {
	server := startDNSTCPServer(t, &dnsTCPServer{hold: true})
	r, err := NewTCPResolver(context.Background(), ResolverConfig{Type: "tcp", Addr: server.addr, Worker: 2}, localDialer())
	require.NoError(t, err)
	r.Send([]byte{1})
	r.Send([]byte{2})
	require.Eventually(t, func() bool { return server.pending.Load() == 2 }, 5*time.Second, 10*time.Millisecond)
	done := make(chan struct{})
	go func() {
		r.Close()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Close waited for answers that never come")
	}
	_, err = r.Read(make([]byte, 16))
	require.Error(t, err)
	r.Send([]byte{3}) // dropped, does not block
	r.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	down := ln.Addr().String()
	ln.Close()
	r, err = NewTCPResolver(context.Background(), ResolverConfig{Type: "tcp", Addr: down, Worker: 1}, localDialer())
	require.NoError(t, err)
	r.Send([]byte{1})
	r.Close()

	_, err = NewTCPResolver(context.Background(), ResolverConfig{Type: "tcp", Addr: down}, localDialer())
	require.Error(t, err, "no worker")
}

// dohRequest is what a DoH server saw of a query.
type dohRequest struct {
	method, path, host string
	contentType        string
	accept             string
	userAgents         int
	proto              int
	sni                string
	grease             bool
}

// dohLog collects the requests of a test DoH server.
type dohLog struct {
	mu       sync.Mutex
	requests []dohRequest
	snis     []string
	grease   []bool
}

func (l *dohLog) hello(sni string, ciphers []uint16) {
	grease := false
	for _, c := range ciphers {
		if c&0x0f0f == 0x0a0a && c>>8 == c&0xff {
			grease = true
		}
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.snis = append(l.snis, sni)
	l.grease = append(l.grease, grease)
}

func (l *dohLog) add(r dohRequest) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.snis) > 0 {
		r.sni = l.snis[len(l.snis)-1]
		r.grease = l.grease[len(l.grease)-1]
	}
	l.requests = append(l.requests, r)
}

func (l *dohLog) all() []dohRequest {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]dohRequest(nil), l.requests...)
}

// forwardDNS sends a query to the xdns server over UDP and returns its
// answer, as a recursive resolver does.
func forwardDNS(udpServer string, query []byte) ([]byte, error) {
	conn, err := net.Dial("udp", udpServer)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(query); err != nil {
		return nil, err
	}
	buf := make([]byte, maxMessage)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

// startStdDoH runs a DoH server of Go's net/http in front of the UDP xdns
// server, with HTTP/2 or HTTP/1.1 only.
func startStdDoH(t *testing.T, cert *testCert, udpServer string, h2 bool, log *dohLog, answer func(query []byte) (int, []byte)) string {
	t.Helper()
	pair, err := stdtls.X509KeyPair(cert.certPEM, cert.keyPEM)
	require.NoError(t, err)
	srv := httptest.NewUnstartedServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		query, _ := io.ReadAll(r.Body)
		log.add(dohRequest{
			method: r.Method, path: r.URL.Path, host: r.Host,
			contentType: r.Header.Get("Content-Type"), accept: r.Header.Get("Accept"),
			userAgents: len(r.Header.Values("User-Agent")), proto: r.ProtoMajor,
		})
		status, body := http.StatusOK, []byte(nil)
		if answer != nil {
			status, body = answer(query)
		}
		if status == http.StatusOK && body == nil {
			var ferr error
			if body, ferr = forwardDNS(udpServer, query); ferr != nil {
				status = http.StatusBadGateway
			}
		}
		if status == http.StatusTooManyRequests {
			w.Header().Set("Retry-After", "1")
		}
		w.Header().Set("Content-Type", "application/dns-message")
		w.WriteHeader(status)
		_, _ = w.Write(body)
	}))
	srv.EnableHTTP2 = h2
	srv.TLS = &stdtls.Config{
		Certificates: []stdtls.Certificate{pair},
		GetConfigForClient: func(hello *stdtls.ClientHelloInfo) (*stdtls.Config, error) {
			log.hello(hello.ServerName, hello.CipherSuites)
			return nil, nil
		},
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv.URL
}

// startH3DoH runs a DoH server over HTTP/3 in front of the UDP xdns server.
func startH3DoH(t *testing.T, cert *testCert, udpServer string, log *dohLog) string {
	t.Helper()
	pair, err := tls.X509KeyPair(cert.certPEM, cert.keyPEM)
	require.NoError(t, err)
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	srv := &http3.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			query, _ := io.ReadAll(r.Body)
			log.add(dohRequest{
				method: r.Method, path: r.URL.Path, host: r.Host,
				contentType: r.Header.Get("Content-Type"), accept: r.Header.Get("Accept"),
				userAgents: len(r.Header.Values("User-Agent")), proto: r.ProtoMajor,
			})
			answer, err := forwardDNS(udpServer, query)
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
				log.hello(hello.ServerName, hello.CipherSuites)
				return nil, nil
			},
		}),
	}
	go func() { _ = srv.Serve(pc) }()
	t.Cleanup(func() {
		_ = srv.Close()
		_ = pc.Close()
	})
	return "https://" + pc.LocalAddr().String()
}

// roundTrip carries packets of the sizes both ways between an xdns client
// and the server.
func roundTrip(t *testing.T, client, server net.PacketConn, sizes []int) {
	t.Helper()
	for _, size := range sizes {
		up := make([]byte, size)
		_, _ = rand.Read(up)
		_, err := client.WriteTo(up, nil)
		require.NoError(t, err)
		buf := make([]byte, 4096)
		n, from, err := readWithTimeout(server, buf, 10*time.Second)
		require.NoError(t, err, "up %d", size)
		require.True(t, bytes.Equal(up, buf[:n]), "up %d", size)

		down := make([]byte, size)
		_, _ = rand.Read(down)
		_, err = server.WriteTo(down, from)
		require.NoError(t, err)
		n, _, err = readWithTimeout(client, buf, 10*time.Second)
		require.NoError(t, err, "down %d", size)
		require.True(t, bytes.Equal(down, buf[:n]), "down %d", size)
	}
}

// The DoH resolver of 10879a4a through a DoH server in front of the xdns
// server: HTTP/2 and HTTP/1.1 as ALPN picks, HTTP/3 with alpn h3; the SNI
// fronts (server-name), the HTTP request names the URL's host, no
// User-Agent goes out and the hello is Chrome's unless unsafe.
func TestDoHRoundTrip(t *testing.T) {
	cert := newTestCert(t)
	cases := []struct {
		name        string
		h3          bool
		h2          bool
		tls         TLSOption
		wantProto   int
		wantGrease  bool
		wantSNI     string
		urlHostname string
	}{
		{name: "h2-chrome-fronted", h2: true, tls: TLSOption{ServerName: "front.example"}, wantProto: 2, wantGrease: true, wantSNI: "front.example"},
		{name: "h1-server-chrome", h2: false, tls: TLSOption{}, wantProto: 1, wantGrease: true, wantSNI: "dns.example", urlHostname: "dns.example"},
		{name: "h2-unsafe", h2: true, tls: TLSOption{Fingerprint: "unsafe", ServerName: "front.example"}, wantProto: 2, wantGrease: false, wantSNI: "front.example"},
		{name: "h1-unsafe-alpn", h2: true, tls: TLSOption{Fingerprint: "unsafe", ALPN: stringList{"http/1.1"}, ServerName: "front.example"}, wantProto: 1, wantGrease: false, wantSNI: "front.example"},
		{name: "h3-fronted", h3: true, tls: TLSOption{ALPN: stringList{"h3"}, ServerName: "front.example"}, wantProto: 3, wantGrease: false, wantSNI: "front.example"},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			serverCfg, err := New(Option{
				Domains:   []DomainOption{{Names: []string{"t.example.com"}, EDNS0: 4096}},
				Resolvers: []ResolverOption{{Addrs: []string{"127.0.0.1"}}},
			})
			require.NoError(t, err)
			server, udpServer := startServer(t, serverCfg)
			log := &dohLog{}
			var base string
			if c.h3 {
				base = startH3DoH(t, cert, udpServer, log)
			} else {
				base = startStdDoH(t, cert, udpServer, c.h2, log, nil)
			}
			url := base + "/dns-query"
			dialer := localDialer()
			if c.urlHostname != "" {
				// The URL names the host; the dial reaches the test server.
				_, port, _ := net.SplitHostPort(strings.TrimPrefix(base, "https://"))
				url = "https://" + c.urlHostname + ":" + port + "/dns-query"
				dialer = redirectDialer(strings.TrimPrefix(base, "https://"))
			}
			tlsOption := c.tls
			tlsOption.PinnedPeerCertSha256 = stringList{pinOf(cert.leafDER)}
			clientCfg, err := New(Option{
				Domains:   []DomainOption{{Names: []string{"t.example.com"}, Types: []int{16}, EDNS0: 4096}},
				Resolvers: []ResolverOption{{Addrs: []string{url}, Worker: 4, TLSConfig: &tlsOption}},
			})
			require.NoError(t, err)
			client, err := clientCfg.WrapPacketConnClient(context.Background(), nil, &finalmask.Destination{Host: "ignored.example", Port: 443}, dialer)
			require.NoError(t, err)
			roundTrip(t, client, server, []int{10, 300, 1200, 2500})
			require.NoError(t, client.Close())
			_, _, err = client.ReadFrom(make([]byte, 16))
			require.Error(t, err)

			requests := log.all()
			require.NotEmpty(t, requests)
			wantHost := strings.TrimPrefix(url, "https://")
			wantHost = wantHost[:strings.Index(wantHost, "/")]
			for _, r := range requests {
				require.Equal(t, "POST", r.method)
				require.Equal(t, "/dns-query", r.path)
				require.Equal(t, wantHost, r.host)
				require.Equal(t, "application/dns-message", r.contentType)
				require.Equal(t, "application/dns-message", r.accept)
				require.Equal(t, 0, r.userAgents, "a User-Agent was sent")
				require.Equal(t, c.wantProto, r.proto)
				require.Equal(t, c.wantSNI, r.sni)
				require.Equal(t, c.wantGrease, r.grease, "Chrome's hello has GREASE, Go's has not")
			}
		})
	}
}

// redirectDialer dials addr whatever the address asked for, as a hosts
// entry would.
func redirectDialer(addr string) *finalmask.Dialer {
	d := localDialer()
	return &finalmask.Dialer{
		DialTCP: func(ctx context.Context, _ string) (net.Conn, error) { return d.DialTCP(ctx, addr) },
		DialUDP: func(ctx context.Context, _ string) (net.PacketConn, net.Addr, error) { return d.DialUDP(ctx, addr) },
	}
}

// A 429 with Retry-After drops the queries until it passes; a 200 that
// fills the 4 KiB buffer is dropped; a certificate that is not pinned fails.
func TestDoHAnswers(t *testing.T) {
	cert := newTestCert(t)
	log := &dohLog{}
	var calls atomic.Int32
	answers := func(query []byte) (int, []byte) {
		switch calls.Add(1) {
		case 1:
			return http.StatusTooManyRequests, []byte{}
		case 2:
			return http.StatusOK, make([]byte, maxMessage+100)
		default:
			return http.StatusOK, append([]byte("answer:"), query...)
		}
	}
	base := startStdDoH(t, cert, "", true, log, answers)
	tlsConfig, err := (&TLSOption{PinnedPeerCertSha256: stringList{pinOf(cert.caDER)}, VerifyPeerCertByName: stringList{"dns.example"}}).Build()
	require.NoError(t, err)
	r, err := NewDOHResolver(context.Background(), ResolverConfig{Type: "https", Addr: base + "/q", Worker: 1, TLS: tlsConfig}, localDialer())
	require.NoError(t, err)
	defer r.Close()

	r.Send([]byte("first"))
	require.Eventually(t, func() bool { return len(log.all()) == 1 }, 5*time.Second, 10*time.Millisecond)
	time.Sleep(100 * time.Millisecond)
	r.Send([]byte("cooling")) // dropped by the Retry-After of 1 s
	time.Sleep(200 * time.Millisecond)
	require.Len(t, log.all(), 1)
	time.Sleep(time.Second)
	r.Send([]byte("long")) // the answer is too long and is dropped
	r.Send([]byte("q"))
	require.Equal(t, []byte("answer:q"), readAnswer(t, r))
	require.Len(t, log.all(), 3)
	require.Equal(t, "127.0.0.1", r.Addr().IP.String())

	// A certificate the pin does not match fails every query.
	bad, err := (&TLSOption{PinnedPeerCertSha256: stringList{strings.Repeat("00", 32)}}).Build()
	require.NoError(t, err)
	r2, err := NewDOHResolver(context.Background(), ResolverConfig{Type: "https", Addr: base + "/q", Worker: 1, TLS: bad}, localDialer())
	require.NoError(t, err)
	r2.Send([]byte("q"))
	time.Sleep(300 * time.Millisecond)
	require.Len(t, log.all(), 3)
	done := make(chan struct{})
	go func() {
		r2.Close()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Close hung")
	}
	_, err = r2.Read(make([]byte, 4))
	require.True(t, errors.Is(err, io.ErrClosedPipe))
}

// Close ends a DoH query that the server never answers.
func TestDoHClose(t *testing.T) {
	cert := newTestCert(t)
	block := make(chan struct{})
	t.Cleanup(func() { close(block) })
	pair, err := stdtls.X509KeyPair(cert.certPEM, cert.keyPEM)
	require.NoError(t, err)
	srv := httptest.NewUnstartedServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		select {
		case <-block:
		case <-r.Context().Done():
		}
	}))
	srv.EnableHTTP2 = true
	srv.TLS = &stdtls.Config{Certificates: []stdtls.Certificate{pair}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	tlsConfig, err := (&TLSOption{PinnedPeerCertSha256: stringList{pinOf(cert.leafDER)}}).Build()
	require.NoError(t, err)
	r, err := NewDOHResolver(context.Background(), ResolverConfig{Type: "https", Addr: srv.URL, Worker: 2, TLS: tlsConfig}, localDialer())
	require.NoError(t, err)
	r.Send([]byte("a"))
	r.Send([]byte("b"))
	time.Sleep(300 * time.Millisecond)
	done := make(chan struct{})
	go func() {
		r.Close()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Close waited for queries the server never answers")
	}
}

// The queries run apart from the context the resolver was made in: a client
// made while XHTTP dials over HTTP/3 has that request's trace hooks in it,
// which the queries must not call. The dials keep its values.
func TestDoHRequestContext(t *testing.T) {
	cert := newTestCert(t)
	base := startStdDoH(t, cert, "", true, &dohLog{}, func(query []byte) (int, []byte) {
		return http.StatusOK, append([]byte("answer:"), query...)
	})
	var hooks atomic.Int32
	type key struct{}
	ctx := httptrace.WithClientTrace(context.WithValue(context.Background(), key{}, "dial"), &httptrace.ClientTrace{
		GetConn: func(string) { hooks.Add(1) },
		GotConn: func(httptrace.GotConnInfo) { hooks.Add(1) },
	})
	ctx, cancel := context.WithCancel(ctx)
	var dialValue atomic.Value
	d := localDialer()
	dialer := &finalmask.Dialer{
		DialTCP: func(ctx context.Context, addr string) (net.Conn, error) {
			dialValue.Store(ctx.Value(key{}))
			return d.DialTCP(ctx, addr)
		},
	}
	tlsConfig, err := (&TLSOption{PinnedPeerCertSha256: stringList{pinOf(cert.leafDER)}}).Build()
	require.NoError(t, err)
	r, err := NewDOHResolver(ctx, ResolverConfig{Type: "https", Addr: base + "/q", Worker: 2, TLS: tlsConfig}, dialer)
	require.NoError(t, err)
	defer r.Close()
	cancel() // the dial that made the client is over
	r.Send([]byte("q"))
	require.Equal(t, []byte("answer:q"), readAnswer(t, r))
	require.Equal(t, int32(0), hooks.Load())
	require.Equal(t, "dial", dialValue.Load())
}

// countingDoH is a DoH server that counts its open connections, the
// handshakes and the requests in flight; it holds each answer for hold, or
// until the request ends when block is set.
type countingDoH struct {
	url      string
	open     atomic.Int32
	hellos   atomic.Int32
	inflight atomic.Int32
	most     atomic.Int32
	answered atomic.Int32
}

func startCountingDoH(t *testing.T, cert *testCert, h2 bool, hold time.Duration, block bool) *countingDoH {
	t.Helper()
	s := &countingDoH{}
	pair, err := stdtls.X509KeyPair(cert.certPEM, cert.keyPEM)
	require.NoError(t, err)
	srv := httptest.NewUnstartedServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		query, _ := io.ReadAll(r.Body)
		n := s.inflight.Add(1)
		for {
			most := s.most.Load()
			if n <= most || s.most.CompareAndSwap(most, n) {
				break
			}
		}
		defer s.inflight.Add(-1)
		if block && len(query) > 0 && query[0] == 'b' {
			<-r.Context().Done()
			return
		}
		time.Sleep(hold)
		s.answered.Add(1)
		_, _ = w.Write(append([]byte("a:"), query...))
	}))
	srv.Config.ConnState = func(_ net.Conn, state stdhttp.ConnState) {
		switch state {
		case stdhttp.StateNew:
			s.open.Add(1)
		case stdhttp.StateClosed, stdhttp.StateHijacked:
			s.open.Add(-1)
		}
	}
	srv.EnableHTTP2 = h2
	srv.TLS = &stdtls.Config{
		Certificates: []stdtls.Certificate{pair},
		GetConfigForClient: func(*stdtls.ClientHelloInfo) (*stdtls.Config, error) {
			s.hellos.Add(1)
			return nil, nil
		},
	}
	if !h2 {
		srv.TLS.NextProtos = []string{"http/1.1"}
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	s.url = srv.URL + "/q"
	return s
}

func pinnedResolver(t *testing.T, cert *testCert, url string, worker int, option TLSOption) Resolver {
	t.Helper()
	option.PinnedPeerCertSha256 = stringList{pinOf(cert.leafDER)}
	tlsConfig, err := option.Build()
	require.NoError(t, err)
	r, err := NewDOHResolver(context.Background(), ResolverConfig{Type: "https", Addr: url, Worker: worker, TLS: tlsConfig}, localDialer())
	require.NoError(t, err)
	return r
}

func drain(r Resolver) *atomic.Int32 {
	var n atomic.Int32
	go func() {
		buf := make([]byte, maxMessage)
		for {
			if _, err := r.Read(buf); err != nil {
				return
			}
			n.Add(1)
		}
	}()
	return &n
}

// Close closes the resolver's connections, those with queries in flight
// too: net/http would keep an HTTP/2 one, its streams just cancelled, until
// it idles out.
func TestDoHCloseClosesConnections(t *testing.T) {
	for _, c := range []struct {
		name     string
		h2       bool
		inflight bool
	}{{"h2-idle", true, false}, {"h2-inflight", true, true}, {"h1-idle", false, false}, {"h1-inflight", false, true}} {
		c := c
		t.Run(c.name, func(t *testing.T) {
			cert := newTestCert(t)
			s := startCountingDoH(t, cert, c.h2, 0, true)
			r := pinnedResolver(t, cert, s.url, 4, TLSOption{})
			answers := drain(r)
			r.Send([]byte("first"))
			require.Eventually(t, func() bool { return answers.Load() == 1 }, 5*time.Second, 5*time.Millisecond)
			if c.inflight {
				r.Send([]byte("b1"))
				r.Send([]byte("b2"))
				require.Eventually(t, func() bool { return s.inflight.Load() == 2 }, 5*time.Second, 5*time.Millisecond)
			}
			require.Greater(t, s.open.Load(), int32(0))
			r.Close()
			require.Eventually(t, func() bool { return s.open.Load() == 0 }, 2*time.Second, 5*time.Millisecond,
				"%d connections open after Close", s.open.Load())
		})
	}
}

// At a cold start the workers wait for the first connection to tell the
// protocol: an HTTP/2 resolver gets one handshake, an HTTP/1.1 one a
// connection per worker, its queries in parallel from the start.
func TestDoHColdStart(t *testing.T) {
	const workers, hold = 8, 300 * time.Millisecond
	for _, c := range []struct {
		name   string
		h2     bool
		option TLSOption
	}{
		{"h2-chrome", true, TLSOption{}},
		{"h1-chrome", false, TLSOption{}},
		{"h1-unsafe", false, TLSOption{Fingerprint: "unsafe"}},
		{"h1-unsafe-alpn", false, TLSOption{Fingerprint: "unsafe", ALPN: stringList{"http/1.1"}}},
	} {
		c := c
		t.Run(c.name, func(t *testing.T) {
			cert := newTestCert(t)
			s := startCountingDoH(t, cert, c.h2, hold, false)
			r := pinnedResolver(t, cert, s.url, workers, c.option)
			defer r.Close()
			answers := drain(r)
			start := time.Now()
			for i := 0; i < workers; i++ {
				go r.Send([]byte{'q', byte(i)})
			}
			require.Eventually(t, func() bool { return answers.Load() == workers }, 10*time.Second, 5*time.Millisecond)
			elapsed := time.Since(start)
			t.Logf("%s: %d queries held %v: %v, at most %d in flight, %d handshakes", c.name, workers, hold, elapsed.Round(time.Millisecond), s.most.Load(), s.hellos.Load())
			// One after another they would take workers*hold.
			require.Less(t, elapsed, 3*hold)
			require.Equal(t, int32(workers), s.most.Load())
			if c.h2 {
				require.Equal(t, int32(1), s.hellos.Load())
			} else {
				require.Equal(t, int32(workers), s.hellos.Load())
			}
		})
	}
}

// A redirect is not followed: the request would leave the mask's dials, by
// plain HTTP if the redirect says so.
func TestDoHRedirectNotFollowed(t *testing.T) {
	cert := newTestCert(t)
	var plainHits atomic.Int32
	plain := httptest.NewServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		plainHits.Add(1)
		_, _ = w.Write([]byte("plain"))
	}))
	defer plain.Close()
	pair, err := stdtls.X509KeyPair(cert.certPEM, cert.keyPEM)
	require.NoError(t, err)
	var redirects atomic.Int32
	srv := httptest.NewUnstartedServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		redirects.Add(1)
		stdhttp.Redirect(w, r, plain.URL+"/leak", stdhttp.StatusTemporaryRedirect)
	}))
	srv.EnableHTTP2 = true
	srv.TLS = &stdtls.Config{Certificates: []stdtls.Certificate{pair}}
	srv.StartTLS()
	defer srv.Close()
	r := pinnedResolver(t, cert, srv.URL+"/q", 1, TLSOption{})
	defer r.Close()
	answers := drain(r)
	r.Send([]byte("q"))
	require.Eventually(t, func() bool { return redirects.Load() == 1 }, 5*time.Second, 5*time.Millisecond)
	time.Sleep(300 * time.Millisecond)
	require.Equal(t, int32(0), plainHits.Load())
	require.Equal(t, int32(0), answers.Load())
}

// Without quic-config an HTTP/3 resolver takes Xray's defaults, path MTU
// discovery off where Xray turns it off.
func TestDoHH3Defaults(t *testing.T) {
	tlsConfig, err := (&TLSOption{ALPN: stringList{"h3"}}).Build()
	require.NoError(t, err)
	r, err := NewDOHResolver(context.Background(), ResolverConfig{Type: "https", Addr: "https://dns.example/q", Worker: 1, TLS: tlsConfig}, localDialer())
	require.NoError(t, err)
	defer r.Close()
	defaults, err := (&QUICOption{}).Build()
	require.NoError(t, err)
	quicConfig := r.(*DOHResolver).client.Transport.(*http3.Transport).QUICConfig
	require.Equal(t, defaults.DisablePathMTUDiscovery, quicConfig.DisablePathMTUDiscovery)
	require.Equal(t, runtime.GOOS != "linux" && runtime.GOOS != "windows" && runtime.GOOS != "darwin", defaults.DisablePathMTUDiscovery)
}

// A tcp resolver bounds its dial; its context carries the caller's values
// but not the trace hooks of an HTTP request.
func TestResolverDialContext(t *testing.T) {
	type key struct{}
	var hooks atomic.Int32
	ctx := httptrace.WithClientTrace(context.WithValue(context.Background(), key{}, "v"), &httptrace.ClientTrace{
		GotConn: func(httptrace.GotConnInfo) { hooks.Add(1) },
	})
	dialed := make(chan context.Context, 1)
	dialer := &finalmask.Dialer{DialTCP: func(ctx context.Context, addr string) (net.Conn, error) {
		dialed <- ctx
		return nil, errors.New("down")
	}}
	r, err := NewTCPResolver(ctx, ResolverConfig{Type: "tcp", Addr: "192.0.2.1:53", Worker: 1}, dialer)
	require.NoError(t, err)
	defer r.Close()
	r.Send([]byte{1})
	var dctx context.Context
	select {
	case dctx = <-dialed:
	case <-time.After(5 * time.Second):
		t.Fatal("no dial")
	}
	deadline, ok := dctx.Deadline()
	require.True(t, ok, "the dial has no deadline")
	require.LessOrEqual(t, time.Until(deadline), dialTimeout)
	require.Equal(t, "v", dctx.Value(key{}))
	require.Nil(t, httptrace.ContextClientTrace(dctx))
	require.Equal(t, int32(0), hooks.Load())
}

// A resolver whose dials keep failing pauses, 1 s after the first failure
// and doubling: the tunnel's queries do not each dial (Xray-core does, and
// a phone runs out of local ports). A dial that works resets the pause.
func TestTCPResolverBackoff(t *testing.T) {
	var dials atomic.Int32
	dialer := &finalmask.Dialer{DialTCP: func(ctx context.Context, addr string) (net.Conn, error) {
		dials.Add(1)
		return nil, errors.New("refused")
	}}
	r, err := NewTCPResolver(context.Background(), ResolverConfig{Type: "tcp", Addr: "192.0.2.1:53", Worker: 4}, dialer)
	require.NoError(t, err)
	defer r.Close()
	for i := 0; i < 50; i++ {
		r.Send([]byte{byte(i)})
	}
	time.Sleep(200 * time.Millisecond)
	first := dials.Load()
	require.GreaterOrEqual(t, first, int32(1))
	require.LessOrEqual(t, first, int32(4), "every query dialed")
	// After the first pause one more attempt goes out.
	time.Sleep(1100 * time.Millisecond)
	for i := 0; i < 50; i++ {
		r.Send([]byte{byte(i)})
	}
	time.Sleep(200 * time.Millisecond)
	require.LessOrEqual(t, dials.Load()-first, int32(4))
	require.Greater(t, dials.Load(), first)
}

// The same for DoH: a server whose TLS never passes is not dialed by every
// query.
func TestDoHBackoff(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()
	var accepted atomic.Int32
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			_ = c.Close()
		}
	}()
	r, err := NewDOHResolver(context.Background(), ResolverConfig{Type: "https", Addr: "https://" + ln.Addr().String() + "/q", Worker: 8}, localDialer())
	require.NoError(t, err)
	defer r.Close()
	for i := 0; i < 100; i++ {
		r.Send([]byte{byte(i)})
		time.Sleep(3 * time.Millisecond)
	}
	require.LessOrEqual(t, accepted.Load(), int32(4), "every query dialed")
	require.GreaterOrEqual(t, accepted.Load(), int32(1))
}
