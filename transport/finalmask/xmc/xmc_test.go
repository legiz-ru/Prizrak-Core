package xmc

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func deriveTestRSAKey(t *testing.T, password string) ([]byte, []byte) {
	t.Helper()
	key, err := DeriveRSAKey(password)
	require.NoError(t, err)
	publicKey, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)
	return x509.MarshalPKCS1PrivateKey(key), publicKey
}

func testLoginProfile(username string) loginProfile {
	profile := loginProfile{
		Username:          username,
		TexturesValue:     strings.Repeat("texture-value-", 40),
		TexturesSignature: strings.Repeat("texture-signature-", 24),
	}
	digest := sha256.Sum256([]byte(username))
	copy(profile.UUID[:], digest[:16])
	profile.UUID[6] = (profile.UUID[6] & 0x0f) | 0x40
	profile.UUID[8] = (profile.UUID[8] & 0x3f) | 0x80
	return profile
}

func TestDeriveRSAKey(t *testing.T) {
	key1, err := DeriveRSAKey("my-very-secret-password-12345")
	require.NoError(t, err)
	require.NoError(t, key1.Validate())
	key2, err := DeriveRSAKey("my-very-secret-password-12345")
	require.NoError(t, err)
	require.Equal(t, 0, key1.D.Cmp(key2.D))
	other, err := DeriveRSAKey("my-very-secret-password-12345-different")
	require.NoError(t, err)
	require.NotEqual(t, 0, key1.N.Cmp(other.N))
}

// The golden hash comes from the Xray fork; the derived key must match its
// servers byte for byte.
func TestDeriveRSAKeyGoldenPrivateKey(t *testing.T) {
	key, err := DeriveRSAKey("deterministic-rsa-key-golden")
	require.NoError(t, err)
	got := sha256.Sum256(x509.MarshalPKCS1PrivateKey(key))
	require.Equal(t, "3a8c4ad56a6fb42dab73c4d5fc3af754460a2db1441edc0970cbc7f4e0798d2f", hex.EncodeToString(got[:]))
}

func TestHandshakeSuccess(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()

	password := "super-secure-shared-key-12345"
	profiles := []loginProfile{testLoginProfile("test_user")}
	privateKey, publicKey := deriveTestRSAKey(t, password)

	serverErr := make(chan error, 1)
	go func() {
		rawConn, err := ln.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer rawConn.Close()
		server, err := wrapConnServer(rawConn, profiles, password, privateKey, publicKey)
		if err != nil {
			serverErr <- err
			return
		}
		buf := make([]byte, 1024)
		n, err := server.Read(buf)
		if err != nil {
			serverErr <- err
			return
		}
		if string(buf[:n]) != "hello server" {
			serverErr <- io.ErrUnexpectedEOF
			return
		}
		_, err = server.Write([]byte("hello client"))
		serverErr <- err
	}()

	clientRaw, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	defer clientRaw.Close()
	client, err := newClientConn(clientRaw, profiles, password, publicKey, "localhost")
	require.NoError(t, err)
	_, err = client.Write([]byte("hello server"))
	require.NoError(t, err)
	buf := make([]byte, 1024)
	n, err := client.Read(buf)
	require.NoError(t, err)
	require.Equal(t, "hello client", string(buf[:n]))
	require.NoError(t, <-serverErr)
}

func TestHandshakePasswordMismatch(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()

	profiles := []loginProfile{testLoginProfile("test_user")}
	serverPrivateKey, serverPublicKey := deriveTestRSAKey(t, "server-secret-456")

	serverErr := make(chan error, 1)
	go func() {
		rawConn, err := ln.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer rawConn.Close()
		server, _ := wrapConnServer(rawConn, profiles, "server-secret-456", serverPrivateKey, serverPublicKey)
		_, err = server.Read(make([]byte, 1024))
		serverErr <- err
	}()

	clientRaw, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	defer clientRaw.Close()
	// Same key (the client knows the server's public key), wrong password.
	client, err := newClientConn(clientRaw, profiles, "client-secret-123", serverPublicKey, "localhost")
	require.NoError(t, err)
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	// The handshake runs inside the first Write and reports the rejection.
	_, err = client.Write([]byte("hello"))
	require.Error(t, err)
	require.Contains(t, err.Error(), "authentication rejected")
	err = <-serverErr
	require.Error(t, err)
	require.Contains(t, err.Error(), "bad password")
}

func TestConfigRoundTrip(t *testing.T) {
	cfg, err := New(Option{
		Password: "shared",
		Hostname: "mc.example.com",
		Profiles: []ProfileOption{{
			Username:          "Steve_01",
			UUID:              "069a79f4-44e9-4726-a5be-fca90e38aaf5",
			TexturesValue:     "value",
			TexturesSignature: "signature",
		}},
	})
	require.NoError(t, err)
	require.Len(t, cfg.Profiles, 1)
	require.Equal(t, 16, len(cfg.Profiles[0].UUID))

	for _, bad := range []Option{
		{Password: "x"},
		{Profiles: []ProfileOption{{Username: "a", UUID: "069a79f4-44e9-4726-a5be-fca90e38aaf5", TexturesValue: "v", TexturesSignature: "s"}}},
		{Password: "x", Profiles: []ProfileOption{{Username: "ab", UUID: "069a79f4-44e9-4726-a5be-fca90e38aaf5", TexturesValue: "v", TexturesSignature: "s"}}},
		{Password: "x", Profiles: []ProfileOption{{Username: "Steve", UUID: "nope", TexturesValue: "v", TexturesSignature: "s"}}},
		{Password: "x", Profiles: []ProfileOption{{Username: "Steve", UUID: "069a79f4-44e9-4726-a5be-fca90e38aaf5"}}},
	} {
		_, err := New(bad)
		require.Error(t, err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()
	payload := bytes.Repeat([]byte("client-payload-"), 5000)
	echo := make(chan error, 1)
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			echo <- err
			return
		}
		defer raw.Close()
		server, err := cfg.WrapConnServer(raw)
		if err != nil {
			echo <- err
			return
		}
		buf := make([]byte, len(payload))
		if _, err := io.ReadFull(server, buf); err != nil {
			echo <- err
			return
		}
		_, err = server.Write(buf)
		echo <- err
	}()
	raw, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	defer raw.Close()
	client, err := cfg.WrapConnClient(context.Background(), raw, nil, nil)
	require.NoError(t, err)
	_ = client.SetDeadline(time.Now().Add(10 * time.Second))
	go func() { _, _ = client.Write(payload) }()
	got := make([]byte, len(payload))
	_, err = io.ReadFull(client, got)
	require.NoError(t, err)
	require.True(t, bytes.Equal(payload, got))
	require.NoError(t, <-echo)
}

func TestPacketStreamUsesPlainFraming(t *testing.T) {
	payload := []byte("hello")
	var wire bytes.Buffer
	stream := newPacketStream(bytes.NewReader(nil), &wire, true)
	written, err := stream.Write(payload)
	require.NoError(t, err)
	require.Equal(t, len(payload), written)
	wantOutbound := []byte{0x0f, 0x02, 0x08, 'x', 'm', 'c', ':', 'd', 'a', 't', 'a', 'h', 'e', 'l', 'l', 'o'}
	require.Equal(t, wantOutbound, wire.Bytes())

	wantInbound := append([]byte(nil), wantOutbound...)
	wantInbound[1] = configurationClientboundCustomPayload
	reader := newPacketStream(bytes.NewReader(wantInbound), io.Discard, true)
	got := make([]byte, len(payload))
	_, err = io.ReadFull(reader, got)
	require.NoError(t, err)
	require.Equal(t, payload, got)
}

func TestProtocol(t *testing.T) {
	r := bytes.NewReader([]byte{0x01, 0x80, 0x01, 0x00})
	_, err := readPacket(r)
	require.Error(t, err)
	pkt, err := readPacket(r)
	require.NoError(t, err)
	require.Equal(t, 0, pkt.packetID)

	var wire bytes.Buffer
	written, err := writePacketWithLength(&wire, 0x03)
	require.NoError(t, err)
	require.Equal(t, 2, written)
	require.Equal(t, []byte{0x01, 0x03}, wire.Bytes())

	_, _, err = readPacketWithLength(bytes.NewReader([]byte{0x81, 0x00, 0x03}))
	require.Error(t, err)
	require.Contains(t, err.Error(), "non-canonical")

	var v Varint
	require.Error(t, v.readFrom(bytes.NewReader([]byte{0xff, 0xff, 0xff, 0xff, 0x10})))
}

func TestPaddingScheduleValidates(t *testing.T) {
	schedule, err := newClientPaddingSchedule2612()
	require.NoError(t, err)
	require.NoError(t, validatePaddingSchedule(schedule, 2))
	schedule, err = newServerPaddingSchedule2612()
	require.NoError(t, err)
	require.NoError(t, validatePaddingSchedule(schedule, 2))
	require.Error(t, validatePaddingSchedule(nil, 0))
}

func TestPaddingTurnRoundTrip(t *testing.T) {
	turn := paddingTurn{direction: paddingClientToServer, minLength: 300, maxLength: 5000, writeChunkLength: 1024}
	var wire bytes.Buffer
	require.NoError(t, writePaddingTurn(&wire, turn, 0))
	require.GreaterOrEqual(t, wire.Len(), 300)
	require.LessOrEqual(t, wire.Len(), 5000)
	require.NoError(t, readPaddingTurn(bytes.NewReader(wire.Bytes()), turn, 0))
	require.Error(t, readPaddingTurn(bytes.NewReader(wire.Bytes()[:100]), turn, 0))
}

func TestDeadlinesRestoreCallerValues(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	d := newConnectionDeadlines(a)
	user := time.Now().Add(time.Hour)
	require.NoError(t, d.setDeadline(user))
	require.NoError(t, d.beginHandshake())
	require.NoError(t, d.endHandshake())
	require.Equal(t, user, d.read)
	require.Equal(t, user, d.write)
}
