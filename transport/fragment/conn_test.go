package fragment

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

type recorder struct {
	net.Conn
	writes [][]byte
}

func (r *recorder) Write(b []byte) (int, error) {
	r.writes = append(r.writes, append([]byte(nil), b...))
	return len(b), nil
}

func (r *recorder) Close() error { return nil }

func (r *recorder) all() []byte { return bytes.Join(r.writes, nil) }

type helloCapture struct {
	net.Conn
	hello []byte
}

func (h *helloCapture) Write(b []byte) (int, error) {
	if h.hello == nil {
		h.hello = append([]byte(nil), b...)
	}
	return len(b), nil
}

func (h *helloCapture) Read([]byte) (int, error)         { return 0, io.EOF }
func (h *helloCapture) Close() error                     { return nil }
func (h *helloCapture) SetDeadline(time.Time) error      { return nil }
func (h *helloCapture) SetReadDeadline(time.Time) error  { return nil }
func (h *helloCapture) SetWriteDeadline(time.Time) error { return nil }

func clientHello(t *testing.T, sni string) []byte {
	t.Helper()
	h := &helloCapture{}
	_ = tls.Client(h, &tls.Config{ServerName: sni, InsecureSkipVerify: true}).Handshake()
	if handshakeRecordLen(h.hello) != len(h.hello) {
		t.Fatalf("captured %d bytes, not one ClientHello record", len(h.hello))
	}
	return h.hello
}

func mustConfig(t *testing.T, o Option) *Config {
	t.Helper()
	cfg, err := NewConfig(o)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

// records splits b into TLS records and checks their headers against want.
func records(t *testing.T, b []byte, header []byte) [][]byte {
	t.Helper()
	var out [][]byte
	for len(b) > 0 {
		if len(b) < 5 || !bytes.Equal(b[:3], header[:3]) {
			t.Fatalf("bad record header % x", b[:5])
		}
		l := int(binary.BigEndian.Uint16(b[3:5]))
		out = append(out, b[5:5+l])
		b = b[5+l:]
	}
	return out
}

func TestTLSHelloOneByteRecordsInOneWrite(t *testing.T) {
	hello := clientHello(t, "www.example.com")
	rec := &recorder{}
	c := NewConn(rec, mustConfig(t, Option{Packets: "tlshello", Length: "1-1", Interval: "0"}))
	if n, err := c.Write(hello); err != nil || n != len(hello) {
		t.Fatal(n, err)
	}
	if len(rec.writes) != 1 {
		t.Fatalf("%d writes, want one with interval 0", len(rec.writes))
	}
	parts := records(t, rec.writes[0], hello)
	if len(parts) != len(hello)-5 {
		t.Fatalf("%d records for %d bytes", len(parts), len(hello)-5)
	}
	for _, p := range parts {
		if len(p) != 1 {
			t.Fatalf("record of %d bytes", len(p))
		}
	}
	if !bytes.Equal(bytes.Join(parts, nil), hello[5:]) {
		t.Fatal("payload changed")
	}
	if !c.WriterReplaceable() {
		t.Fatal("not replaceable after the ClientHello")
	}
	if _, err := c.Write([]byte("next")); err != nil || string(rec.writes[1]) != "next" {
		t.Fatal("later write changed")
	}
}

func TestTLSHelloRecordsSeparately(t *testing.T) {
	hello := clientHello(t, "www.example.com")
	rec := &recorder{}
	c := NewConn(rec, mustConfig(t, Option{Packets: "tlshello", Length: "100-200", Interval: "1-2"}))
	if _, err := c.Write(hello); err != nil {
		t.Fatal(err)
	}
	if len(rec.writes) < 2 {
		t.Fatalf("%d writes, want one per record", len(rec.writes))
	}
	var parts [][]byte
	for _, w := range rec.writes {
		p := records(t, w, hello)
		if len(p) != 1 {
			t.Fatalf("write carries %d records", len(p))
		}
		if len(p[0]) > 199 {
			t.Fatalf("record of %d bytes, length is [100, 200)", len(p[0]))
		}
		parts = append(parts, p[0])
	}
	if !bytes.Equal(bytes.Join(parts, nil), hello[5:]) {
		t.Fatal("payload changed")
	}
}

func TestTLSHelloMaxSplit(t *testing.T) {
	hello := clientHello(t, "www.example.com")
	rec := &recorder{}
	c := NewConn(rec, mustConfig(t, Option{Packets: "tlshello", Length: "1-1", Interval: "0", MaxSplit: "3"}))
	if _, err := c.Write(hello); err != nil {
		t.Fatal(err)
	}
	if parts := records(t, rec.all(), hello); len(parts) != 3 {
		t.Fatalf("%d records, want 3", len(parts))
	}
}

func TestTLSHelloSplitAtServerName(t *testing.T) {
	const sni = "www.blocked-site.example.com"
	hello := clientHello(t, sni)
	rec := &recorder{}
	c := NewConn(rec, mustConfig(t, Option{Packets: "tlshello", Split: "sni"}))
	if _, err := c.Write(hello); err != nil {
		t.Fatal(err)
	}
	parts := records(t, rec.all(), hello)
	if len(parts) != 4 { // www, blocked-site, example cut; com is kept whole
		t.Fatalf("%d records, want 4", len(parts))
	}
	for _, p := range parts {
		for _, label := range []string{"www", "blocked-site", "example"} {
			if bytes.Contains(p, []byte(label)) {
				t.Fatalf("a record carries the whole label %q", label)
			}
		}
	}
	if !bytes.Equal(bytes.Join(parts, nil), hello[5:]) {
		t.Fatal("payload changed")
	}
}

func TestClientHelloInPieces(t *testing.T) {
	hello := clientHello(t, "www.example.com")
	rec := &recorder{}
	c := NewConn(rec, mustConfig(t, Option{Packets: "tlshello", Length: "1-1", Interval: "0"}))
	for _, part := range [][]byte{hello[:3], hello[3:100], hello[100:]} {
		if n, err := c.Write(part); err != nil || n != len(part) {
			t.Fatal(n, err)
		}
	}
	if len(rec.writes) != 1 {
		t.Fatalf("%d writes, want the record held until complete", len(rec.writes))
	}
	if parts := records(t, rec.writes[0], hello); !bytes.Equal(bytes.Join(parts, nil), hello[5:]) || len(parts) != len(hello)-5 {
		t.Fatal("ClientHello in pieces not fragmented")
	}
}

func TestNotTLSPassesThrough(t *testing.T) {
	rec := &recorder{}
	c := NewConn(rec, mustConfig(t, Option{Packets: "tlshello", Length: "1-1"}))
	req := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	if _, err := c.Write(req); err != nil {
		t.Fatal(err)
	}
	if len(rec.writes) != 1 || !bytes.Equal(rec.writes[0], req) || !c.WriterReplaceable() {
		t.Fatal("plain data changed")
	}
}

func TestSegmentsOfARange(t *testing.T) {
	rec := &recorder{}
	c := NewConn(rec, mustConfig(t, Option{Packets: "1-2", Length: "3"}))
	for _, w := range []string{"0123456789", "abcde", "rest"} {
		if _, err := c.Write([]byte(w)); err != nil {
			t.Fatal(err)
		}
	}
	var got []string
	for _, w := range rec.writes {
		got = append(got, string(w))
	}
	if want := "012|345|678|9|abc|de|rest"; strings.Join(got, "|") != want {
		t.Fatalf("writes %q, want %q", strings.Join(got, "|"), want)
	}
	if !c.WriterReplaceable() {
		t.Fatal("not replaceable after the last fragmented packet")
	}
}

func TestSegmentsAtServerName(t *testing.T) {
	hello := clientHello(t, "www.example.com")
	rec := &recorder{}
	c := NewConn(rec, mustConfig(t, Option{Packets: "1-1", Split: "sni"}))
	if _, err := c.Write(hello); err != nil {
		t.Fatal(err)
	}
	if len(rec.writes) != 3 || !bytes.Equal(rec.all(), hello) {
		t.Fatalf("%d segments, want the ClientHello cut in www and example", len(rec.writes))
	}
}

func TestWaitAckOverTCP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := make(chan []byte, 1)
	go func() {
		s, err := ln.Accept()
		if err != nil {
			return
		}
		defer s.Close()
		b, _ := io.ReadAll(s)
		got <- b
	}()
	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	c := NewConn(raw, mustConfig(t, Option{Packets: "1-1", Length: "2", Wait: "ack", FallbackDelay: 1}))
	if _, err := c.Write([]byte("abcdef")); err != nil {
		t.Fatal(err)
	}
	c.Close()
	select {
	case b := <-got:
		if string(b) != "abcdef" {
			t.Fatalf("server read %q", b)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout")
	}
}

func TestConfigErrors(t *testing.T) {
	for _, o := range []Option{
		{Packets: "tlshello"},                          // no length
		{Packets: "0-3", Length: "1"},                  // packets start at 1
		{Packets: "tlshello", Length: "0-5"},           // zero length
		{Packets: "tlshello", Split: "words"},          // unknown split
		{Packets: "tlshello", Split: "sni", Wait: "x"}, // unknown wait
		{Packets: "x-y", Length: "1"},
	} {
		if _, err := NewConfig(o); err == nil {
			t.Fatalf("%+v accepted", o)
		}
	}
	cfg, err := NewConfig(Option{Packets: "tlshello", Split: "sni"})
	if err != nil || !cfg.TLSHello() || !cfg.SplitSNI || cfg.FallbackDelay != DefaultFallbackDelay {
		t.Fatal(cfg, err)
	}
	if _, _, err := parseRange("5-2"); err != nil {
		t.Fatal(err)
	}
	if a, b, _ := parseRange("5-2"); a != 2 || b != 5 {
		t.Fatal("reversed range not swapped")
	}
}
