package ech

import (
	"bytes"
	"context"
	"testing"

	utls "github.com/metacubex/utls"
)

func TestClientHandleUTLSInstallsECHConfigAfterConversion(t *testing.T) {
	want := []byte{1, 2, 3, 4}
	config := &Config{GetEncryptedClientHelloConfigList: func(context.Context, string) ([]byte, error) {
		return bytes.Clone(want), nil
	}}
	uTLSConfig := &utls.Config{ServerName: "example.com"}
	if err := config.ClientHandleUTLS(context.Background(), uTLSConfig); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(uTLSConfig.EncryptedClientHelloConfigList, want) {
		t.Fatalf("uTLS ECH config list = %v, want %v", uTLSConfig.EncryptedClientHelloConfigList, want)
	}
}
