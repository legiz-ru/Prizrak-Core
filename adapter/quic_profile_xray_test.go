package adapter

import (
	"net"
	"sync"
	"testing"
)

// XHTTP over HTTP/3 to Xray's vless inbound with each browser of
// client-fingerprint (Chrome's by default) and with disable-chrome-parrot,
// through a relay that records the client's Initials: the proxy works, and
// its first flight has the profile's shape.
//
//	XRAY_BIN=/path/to/xray go test ./adapter/ -run TestXrayXHTTP3QUICProfile -v

type quicProfileXrayCase struct {
	name        string
	disable     bool   // disable-chrome-parrot
	fingerprint string // client-fingerprint, unset when empty
	size        int    // of each Initial datagram of the first flight
	scid        int    // source connection ID length
}

var quicProfileXrayCases = []quicProfileXrayCase{
	{"off", true, "chrome", 1280, 0},
	{"default", false, "", 1250, 0},
	{"chrome", false, "chrome", 1250, 0},
	{"firefox", false, "firefox", 1252, 3},
	{"safari", false, "safari", 1200, 0},
}

// apply sets the case's keys on a proxy's mapping.
func (c quicProfileXrayCase) apply(m map[string]any) map[string]any {
	if c.fingerprint != "" {
		m["client-fingerprint"] = c.fingerprint
	}
	if c.disable {
		m["disable-chrome-parrot"] = true
	}
	return m
}

// initialRecorder relays UDP from a port to target, one upstream socket per
// client, and records the size and source connection ID length of every
// client datagram that starts with an Initial.
type initialRecorder struct {
	mu       sync.Mutex
	initials [][2]int
}

func (r *initialRecorder) relay(t *testing.T, target int) int {
	t.Helper()
	ln, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	targetAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: target}
	go func() {
		upstreams := map[string]*net.UDPConn{}
		buf := make([]byte, 65535)
		for {
			n, from, err := ln.ReadFrom(buf)
			if err != nil {
				return
			}
			if n > 7 && buf[0]&0x80 != 0 && buf[0]&0x30 == 0 {
				if dcid := int(buf[5]); 6+dcid < n {
					r.mu.Lock()
					r.initials = append(r.initials, [2]int{n, int(buf[6+dcid])})
					r.mu.Unlock()
				}
			}
			up := upstreams[from.String()]
			if up == nil {
				up, err = net.DialUDP("udp", nil, targetAddr)
				if err != nil {
					return
				}
				upstreams[from.String()] = up
				go func(up *net.UDPConn, from net.Addr) {
					b := make([]byte, 65535)
					for {
						n, err := up.Read(b)
						if err != nil {
							return
						}
						_, _ = ln.WriteTo(b[:n], from)
					}
				}(up, from)
				t.Cleanup(func() { up.Close() })
			}
			_, _ = up.Write(buf[:n])
		}
	}()
	return ln.LocalAddr().(*net.UDPAddr).Port
}

func (r *initialRecorder) first() ([2]int, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.initials) == 0 {
		return [2]int{}, false
	}
	return r.initials[0], true
}

func TestXrayXHTTP3QUICProfile(t *testing.T) {
	bin := xrayBinary(t)
	echoPort := echoServer(t)
	// The browsers offer no Ed25519 signature: the certificate is ECDSA.
	certFile, keyFile := writeCert(t, t.TempDir())

	port := freePort(t, "udp")
	stream := map[string]any{
		"network":       "xhttp",
		"xhttpSettings": map[string]any{"path": "/x"},
	}
	for k, v := range tlsStream(certFile, keyFile, []string{"h3"}) {
		stream[k] = v
	}
	startXray(t, bin, xrayServer{proto: "vless", stream: stream, port: port, network: "udp", readyTCP: freePort(t, "tcp")})

	for _, tc := range quicProfileXrayCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			rec := &initialRecorder{}
			front := rec.relay(t, port)
			proxy, err := ParseProxy(tc.apply(map[string]any{
				"name": "vless-h3-" + tc.name, "type": "vless", "server": "127.0.0.1", "port": front, "uuid": xrayUUID,
				"network": "xhttp", "xhttp-opts": map[string]any{"path": "/x"},
				"tls": true, "alpn": []any{"h3"}, "servername": "localhost", "skip-cert-verify": true,
			}))
			if err != nil {
				t.Fatal(err)
			}
			defer proxy.Close()
			echoThrough(t, proxy, echoPort, 256*1024)

			first, ok := rec.first()
			if !ok {
				t.Fatal("no Initial seen")
			}
			if first[0] != tc.size || first[1] != tc.scid {
				t.Fatalf("first Initial: size %d, scid %d; want size %d, scid %d", first[0], first[1], tc.size, tc.scid)
			}
		})
	}
}

// Through a finalmask UDP chain the QUIC connection is dialed by
// finalMaskDialQUIC, which gives its Transport the profile's connection IDs
// as DialQuic does.
func TestXrayXHTTP3QUICProfileFinalMask(t *testing.T) {
	bin := xrayBinary(t)
	echoPort := echoServer(t)
	certFile, keyFile := writeCert(t, t.TempDir())
	pair := udpMaskPairs(0)[0] // noise
	port := freePort(t, "udp")
	stream := map[string]any{
		"network":       "xhttp",
		"xhttpSettings": map[string]any{"path": "/x"},
		"finalmask":     pair.xray,
	}
	for k, v := range tlsStream(certFile, keyFile, []string{"h3"}) {
		stream[k] = v
	}
	startXray(t, bin, xrayServer{proto: "vless", stream: stream, port: port, network: "udp", readyTCP: freePort(t, "tcp")})
	for _, tc := range quicProfileXrayCases {
		tc := tc
		t.Run(pair.name+"/"+tc.name, func(t *testing.T) {
			proxy, err := ParseProxy(tc.apply(map[string]any{
				"name": "vless-h3-mask-" + tc.name, "type": "vless", "server": "127.0.0.1", "port": port, "uuid": xrayUUID,
				"network": "xhttp", "xhttp-opts": map[string]any{"path": "/x"},
				"tls": true, "alpn": []any{"h3"}, "servername": "localhost", "skip-cert-verify": true,
				"finalmask": pair.core,
			}))
			if err != nil {
				t.Fatal(err)
			}
			defer proxy.Close()
			echoThrough(t, proxy, echoPort, 64*1024)
		})
	}
}
