package tls

import (
	"context"
	gotls "crypto/tls"
	"net"
	"testing"
	"time"

	utls "github.com/metacubex/utls"
	"github.com/stretchr/testify/assert"
)

// Fingerprints that send key shares for X25519 and then P-256 complete a
// handshake with a server that selects P-256, using the key share they sent
// (refraction-networking/utls#402).
func TestSecondaryKeyShareSelectedByServer(t *testing.T) {
	cert := selfSignedCert(t)
	for _, name := range []string{"firefox", "firefox120"} {
		fingerprint, ok := GetFingerprint(name)
		if !assert.True(t, ok) {
			continue
		}
		t.Run(name, func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if !assert.NoError(t, err) {
				return
			}
			defer ln.Close()
			done := make(chan error, 1)
			go func() {
				server, err := ln.Accept()
				if err != nil {
					done <- err
					return
				}
				conn := gotls.Server(server, &gotls.Config{Certificates: []gotls.Certificate{cert}, CurvePreferences: []gotls.CurveID{gotls.CurveP256}})
				done <- conn.HandshakeContext(context.Background())
				_ = conn.Close()
			}()
			client, err := net.Dial("tcp", ln.Addr().String())
			if !assert.NoError(t, err) {
				return
			}
			uConn := UClient(client, &utls.Config{ServerName: "example.com", InsecureSkipVerify: true}, fingerprint)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			err = uConn.HandshakeContext(ctx)
			cancel()
			// The client's state: crypto/tls has CurveID and HelloRetryRequest
			// only since Go 1.25.
			state := uConn.ConnectionState()
			_ = uConn.Close()
			serverErr := <-done
			if assert.NoError(t, err) && assert.NoError(t, serverErr) {
				assert.Equal(t, utls.CurveP256, state.CurveID)
				assert.False(t, state.HelloRetryRequest, "the P-256 key share the client sent must be used")
			}
		})
	}
}
