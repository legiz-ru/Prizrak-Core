package tls

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	gotls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"

	utls "github.com/metacubex/utls"
	"github.com/stretchr/testify/assert"
	"golang.org/x/exp/slices"
)

func randomizedWithSeed(t *testing.T) UClientHelloID {
	fingerprint := utls.HelloRandomized
	seed, err := utls.NewPRNGSeed()
	if !assert.NoError(t, err) {
		t.FailNow()
	}
	fingerprint.Seed = seed
	fingerprint.Weights = &randomizedWeights
	return fingerprint
}

func helloGroups(uConn *UConn) (curves []utls.CurveID, shares []utls.CurveID) {
	for _, extension := range uConn.Extensions {
		switch ext := extension.(type) {
		case *utls.SupportedCurvesExtension:
			curves = append(curves, ext.Curves...)
		case *utls.KeyShareExtension:
			for _, share := range ext.KeyShares {
				shares = append(shares, share.Group)
			}
		}
	}
	return
}

// Every process's "randomized" hello offers X25519MLKEM768 with its key share,
// sends key shares for X25519MLKEM768 and X25519 only, and no key share for a
// group it does not offer.
func TestRandomizedHelloAlwaysOffersMLKEMWithItsKeyShare(t *testing.T) {
	for i := 0; i < 200; i++ {
		client, server := net.Pipe()
		uConn := UClient(client, &utls.Config{ServerName: "example.com"}, randomizedWithSeed(t))
		curves, shares := helloGroups(uConn)
		_ = client.Close()
		_ = server.Close()
		var classical []utls.CurveID
		for _, share := range shares {
			if share>>8 == 0x0a && share&0xff == 0x0a { // GREASE
				continue
			}
			classical = append(classical, share)
			assert.Contains(t, curves, share, "key share for a group that is not offered")
		}
		assert.Contains(t, curves, utls.X25519MLKEM768)
		assert.Equal(t, []utls.CurveID{utls.X25519MLKEM768, utls.X25519}, classical)
		if t.Failed() {
			t.Logf("seed %d: groups %v, key shares %v", i, curves, shares)
			return
		}
	}
}

func selfSignedCert(t *testing.T) gotls.Certificate {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if !assert.NoError(t, err) {
		t.FailNow()
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "example.com"},
		DNSNames:     []string{"example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if !assert.NoError(t, err) {
		t.FailNow()
	}
	return gotls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// A "randomized" client completes a handshake with a server that prefers the
// hybrid group and with one that only takes P-256, which asks again.
func TestRandomizedHelloHandshakes(t *testing.T) {
	cert := selfSignedCert(t)
	for name, curves := range map[string][]gotls.CurveID{
		"default": nil,
		"P-256":   {gotls.CurveP256},
		"X25519":  {gotls.X25519},
	} {
		curves := curves
		t.Run(name, func(t *testing.T) {
			for i := 0; i < 20; i++ {
				ln, err := net.Listen("tcp", "127.0.0.1:0")
				if !assert.NoError(t, err) {
					return
				}
				done := make(chan error, 1)
				go func() {
					server, err := ln.Accept()
					if err != nil {
						done <- err
						return
					}
					conn := gotls.Server(server, &gotls.Config{Certificates: []gotls.Certificate{cert}, CurvePreferences: curves})
					done <- conn.HandshakeContext(context.Background())
					_ = conn.Close()
				}()
				client, err := net.Dial("tcp", ln.Addr().String())
				if !assert.NoError(t, err) {
					return
				}
				uConn := UClient(client, &utls.Config{ServerName: "example.com", InsecureSkipVerify: true}, randomizedWithSeed(t))
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				err = uConn.HandshakeContext(ctx)
				cancel()
				_ = uConn.Close()
				serverErr := <-done
				_ = ln.Close()
				if !assert.NoError(t, err) || !assert.NoError(t, serverErr) {
					return
				}
			}
		})
	}
}

func TestRandomFingerprintOffersMLKEM(t *testing.T) {
	for _, name := range []string{"chrome", "safari", "firefox"} {
		fingerprint, ok := GetFingerprint(name)
		if !assert.True(t, ok, name) {
			continue
		}
		client, server := net.Pipe()
		uConn := UClient(client, &utls.Config{ServerName: "example.com"}, fingerprint)
		assert.NoError(t, uConn.BuildHandshakeState())
		curves, shares := helloGroups(uConn)
		_ = client.Close()
		_ = server.Close()
		assert.True(t, slices.Contains(curves, utls.X25519MLKEM768) && slices.Contains(shares, utls.X25519MLKEM768), "%s: groups %v, key shares %v", name, curves, shares)
	}
}
