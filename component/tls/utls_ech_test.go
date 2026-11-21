package tls

import (
	"bytes"
	"testing"

	"github.com/metacubex/tls"
)

func TestUConfigPreservesExplicitECHConfigList(t *testing.T) {
	list := []byte{0, 1, 2, 3, 4, 5}
	standard := &tls.Config{EncryptedClientHelloConfigList: bytes.Clone(list)}
	got := UConfig(standard)
	if !bytes.Equal(got.EncryptedClientHelloConfigList, list) {
		t.Fatalf("uTLS ECH config list = %v, want %v", got.EncryptedClientHelloConfigList, list)
	}
	if !bytes.Equal(standard.EncryptedClientHelloConfigList, list) {
		t.Fatalf("source TLS ECH config list was mutated: %v", standard.EncryptedClientHelloConfigList)
	}
}
