package adapter

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"testing"
)

// The QUIC clients other than hysteria2, vless over HTTP/3 and xdns DoH keep
// quic-go's own handshake: no Parrot reaches their configs, so DialQuic
// leaves their Transport's connection IDs alone. TUIC's Initial is quic-go's
// 1280 bytes with an empty source connection ID, MASQUE's its own 1242 bytes
// with a 20-byte one.
func TestQUICWithoutParrot(t *testing.T) {
	size, scid := captureFirstInitial(t, func(port int) map[string]any {
		return map[string]any{
			"name": "tuic", "type": "tuic", "server": "127.0.0.1", "port": port,
			"uuid": xrayUUID, "password": "pw", "alpn": []any{"h3"}, "skip-cert-verify": true,
		}
	})
	if size != 1280 || scid != 0 {
		t.Errorf("tuic: size %d, scid %d; want 1280, 0", size, scid)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privateKey, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	size, scid = captureFirstInitial(t, func(port int) map[string]any {
		return map[string]any{
			"name": "masque", "type": "masque", "server": "127.0.0.1", "port": port,
			"private-key": base64.StdEncoding.EncodeToString(privateKey),
			"public-key":  base64.StdEncoding.EncodeToString(publicKey),
			"ip":          "172.16.0.2/32", "udp": true,
		}
	})
	if size != 1242 || scid != 20 {
		t.Errorf("masque: size %d, scid %d; want 1242, 20", size, scid)
	}
}
