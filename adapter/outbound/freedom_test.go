package outbound

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	N "github.com/metacubex/mihomo/common/net"
	C "github.com/metacubex/mihomo/constant"
)

// TestFreedomFragmentsClientHello dials a local TLS server through freedom
// with Xray's tlshello settings: the server sees the ClientHello split into
// one-byte records and the handshake still completes.
// recordServer accepts one connection and reports in how many TLS records
// the first handshake message arrived.
func recordServer(t *testing.T) (*net.TCPAddr, <-chan int) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	firstRecords := make(chan int, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		var payload []byte
		records := 0
		hdr := make([]byte, 5)
		for {
			if _, err := io.ReadFull(c, hdr); err != nil {
				firstRecords <- -1
				return
			}
			body := make([]byte, int(hdr[3])<<8|int(hdr[4]))
			if _, err := io.ReadFull(c, body); err != nil {
				firstRecords <- -1
				return
			}
			records++
			payload = append(payload, body...)
			if len(payload) >= 4 && len(payload) >= 4+(int(payload[1])<<16|int(payload[2])<<8|int(payload[3])) {
				break
			}
		}
		firstRecords <- records
	}()
	return ln.Addr().(*net.TCPAddr), firstRecords
}

func newTestFreedom(t *testing.T) *Freedom {
	proxy, err := NewFreedom(FreedomOption{
		Name:     "FRAGMENT",
		Fragment: &FreedomFragmentOption{Packets: "tlshello", Length: "1-1", Interval: "0"},
		Sockopt: &FreedomSockoptOption{
			TCPKeepAliveIdle:     300,
			TCPKeepAliveInterval: 60,
			TCPUserTimeout:       10000,
			CustomSockopt:        []FreedomCustomSockopt{{Opt: "1", Type: "int", Value: "1"}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if proxy.Type() != C.Freedom {
		t.Fatalf("type %v", proxy.Type())
	}
	return proxy
}

func dialFreedom(ctx context.Context, t *testing.T, proxy *Freedom, addr *net.TCPAddr) C.Conn {
	conn, err := proxy.DialContext(ctx, &C.Metadata{
		NetWork: C.TCP,
		DstIP:   netip.MustParseAddr("127.0.0.1"),
		DstPort: uint16(addr.Port),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

func expectOneByteRecords(ctx context.Context, t *testing.T, firstRecords <-chan int) {
	select {
	case n := <-firstRecords:
		if n < 100 {
			t.Fatalf("ClientHello came in %d records, want one per byte", n)
		}
	case <-ctx.Done():
		t.Fatal("timeout")
	}
}

// TestFreedomFragmentsClientHello dials a local server through freedom with
// Xray's tlshello settings: the server sees the ClientHello split into
// one-byte records.
func TestFreedomFragmentsClientHello(t *testing.T) {
	addr, firstRecords := recordServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn := dialFreedom(ctx, t, newTestFreedom(t), addr)
	tc := tls.Client(conn, &tls.Config{ServerName: "www.example.com", InsecureSkipVerify: true})
	go func() { _ = tc.HandshakeContext(ctx) }()
	expectOneByteRecords(ctx, t, firstRecords)
}

// The same through the relay the tunnel uses, which unwraps connections to
// copy between the sockets directly: the fragment wrapper must not be skipped.
func TestFreedomFragmentsThroughRelay(t *testing.T) {
	addr, firstRecords := recordServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	outbound := dialFreedom(ctx, t, newTestFreedom(t), addr)

	inLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer inLn.Close()
	go func() {
		inbound, err := inLn.Accept()
		if err != nil {
			return
		}
		N.Relay(inbound, outbound)
	}()
	app, err := net.Dial("tcp", inLn.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	tc := tls.Client(app, &tls.Config{ServerName: "www.example.com", InsecureSkipVerify: true})
	go func() { _ = tc.HandshakeContext(ctx) }()
	expectOneByteRecords(ctx, t, firstRecords)
}

func TestFreedomOptionErrors(t *testing.T) {
	if _, err := NewFreedom(FreedomOption{Name: "x", Fragment: &FreedomFragmentOption{Packets: "tlshello"}}); err == nil {
		t.Fatal("fragment without length accepted")
	}
	if _, err := NewFreedom(FreedomOption{Name: "x", Sockopt: &FreedomSockoptOption{
		CustomSockopt: []FreedomCustomSockopt{{Opt: "a", Value: "1"}},
	}}); err == nil {
		t.Fatal("bad custom-sockopt accepted")
	}
}
