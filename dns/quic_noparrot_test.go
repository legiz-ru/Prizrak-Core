package dns

import (
	"context"
	"net"
	"testing"
	"time"

	D "github.com/miekg/dns"
)

// The DNS client's DoQ and DoH over HTTP/3 keep quic-go's own handshake, as
// in Xray's DNS: the browser handshakes of the proxies do not reach them.
// Their first Initial is quic-go's 1280 bytes (Chrome's would be 1250,
// Firefox's 1252, Safari's 1200).
func TestQUICClientsWithoutParrot(t *testing.T) {
	for _, tc := range []struct {
		name   string
		client func(addr string) dnsClient
	}{
		{"doq", func(addr string) dnsClient {
			return newDoQ(addr, nil, map[string]string{"skip-cert-verify": "true"}, nil, "")
		}},
		{"doh3", func(addr string) dnsClient {
			return newDoHClient("https://"+addr+"/dns-query", nil, false, map[string]string{"h3": "true", "skip-cert-verify": "true"}, nil, "")
		}},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			capture, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer capture.Close()
			client := tc.client(capture.LocalAddr().String())
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			go func() {
				m := new(D.Msg)
				m.SetQuestion("example.com.", D.TypeA)
				_, _ = client.ExchangeContext(ctx, m)
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
			if n != 1280 {
				t.Errorf("%s: an Initial of %d bytes, want quic-go's 1280", tc.name, n)
			}
		})
	}
}
