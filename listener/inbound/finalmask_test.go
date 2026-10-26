package inbound_test

import (
	"net"
	"testing"

	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/listener/inbound"
	"github.com/metacubex/mihomo/transport/finalmask/option"

	"github.com/stretchr/testify/assert"
)

// finalMaskChain is a TCP chain both ends share: a scripted header, sudoku
// and fragmentation, the last one on the wire.
func finalMaskChain() option.Option {
	return option.Option{TCP: []map[string]any{
		{"type": "header-custom",
			"clients": []any{[]any{map[string]any{"type": "str", "packet": "GET / HTTP/1.1\r\n"}, map[string]any{"rand": 4, "capture": "n"}}},
			"servers": []any{[]any{map[string]any{"type": "str", "packet": "HTTP/1.1 101\r\n"}, map[string]any{"reuse": "n"}}},
		},
		{"type": "sudoku", "password": "finalmask", "custom-tables": []any{"xpxvvpvv", "vxpvxvvp"}, "padding-min": 10, "padding-max": 20},
		{"type": "fragment", "packets": "1-2", "length": "10-20"},
	}}
}

func finalMaskOutbound() *outbound.FinalMaskOption {
	o := finalMaskChain()
	return &o
}

func TestInboundVless_FinalMask(t *testing.T) {
	testInboundVless(t,
		inbound.VlessOption{AllowInsecure: true, FinalMask: finalMaskChain()},
		outbound.VlessOption{FinalMask: finalMaskOutbound()})
}

func TestInboundVless_FinalMask_Ws(t *testing.T) {
	testInboundVless(t,
		inbound.VlessOption{AllowInsecure: true, WsPath: "/ws", FinalMask: finalMaskChain()},
		outbound.VlessOption{Network: "ws", WSOpts: outbound.WSOptions{Path: "/ws"}, FinalMask: finalMaskOutbound()})
}

func TestInboundVless_FinalMask_Grpc(t *testing.T) {
	testInboundVless(t,
		inbound.VlessOption{AllowInsecure: true, GrpcServiceName: "svc", FinalMask: finalMaskChain()},
		outbound.VlessOption{Network: "grpc", GrpcOpts: outbound.GrpcOptions{GrpcServiceName: "svc"}, FinalMask: finalMaskOutbound()})
}

func TestInboundVless_FinalMask_Xhttp(t *testing.T) {
	testInboundVless(t,
		inbound.VlessOption{AllowInsecure: true, XHTTPConfig: inbound.XHTTPConfig{Path: "/x"}, FinalMask: finalMaskChain()},
		outbound.VlessOption{Network: "xhttp", XHTTPOpts: outbound.XHTTPOptions{Path: "/x"}, FinalMask: finalMaskOutbound()})
}

// The trojan client is TLS-only, so its listeners get a cert.
func TestInboundTrojan_FinalMask_Wss(t *testing.T) {
	testInboundTrojan(t,
		inbound.TrojanOption{Certificate: tlsCertificate, PrivateKey: tlsPrivateKey, WsPath: "/ws", FinalMask: finalMaskChain()},
		outbound.TrojanOption{Network: "ws", WSOpts: outbound.WSOptions{Path: "/ws"}, Fingerprint: tlsFingerprint, FinalMask: finalMaskOutbound()})
}

func TestInboundTrojan_FinalMask_TLS(t *testing.T) {
	testInboundTrojan(t,
		inbound.TrojanOption{Certificate: tlsCertificate, PrivateKey: tlsPrivateKey, FinalMask: finalMaskChain()},
		outbound.TrojanOption{Fingerprint: tlsFingerprint, FinalMask: finalMaskOutbound()})
}

// The masks sit under TLS: the listener's TLS reads through them.
func TestInboundVless_FinalMask_TLS(t *testing.T) {
	testInboundVless(t,
		inbound.VlessOption{Certificate: tlsCertificate, PrivateKey: tlsPrivateKey, FinalMask: finalMaskChain()},
		outbound.VlessOption{TLS: true, Fingerprint: tlsFingerprint, FinalMask: finalMaskOutbound()})
}

// A listener has no HTTP/3 socket, so UDP masks have nowhere to go.
func TestInboundFinalMaskRejectsUDP(t *testing.T) {
	in, err := inbound.NewVless(&inbound.VlessOption{
		BaseOption:    inbound.BaseOption{NameStr: "vless_udp_mask", Listen: "127.0.0.1", Port: "0"},
		Users:         []inbound.VlessUser{{Username: "test", UUID: userUUID}},
		AllowInsecure: true,
		FinalMask:     option.Option{UDP: []map[string]any{{"type": "noise", "noise": []any{map[string]any{"rand": 8}}}}},
	})
	assert.NoError(t, err)
	tunnel := NewHttpTestTunnel()
	defer tunnel.Close()
	assert.Error(t, in.Listen(tunnel))

	in, err = inbound.NewVless(&inbound.VlessOption{
		BaseOption:    inbound.BaseOption{NameStr: "vless_bad_mask", Listen: "127.0.0.1", Port: "0"},
		Users:         []inbound.VlessUser{{Username: "test", UUID: userUUID}},
		AllowInsecure: true,
		FinalMask:     option.Option{TCP: []map[string]any{{"type": "mkcp-legacy"}}},
	})
	assert.NoError(t, err)
	assert.Error(t, in.Listen(tunnel))
}

// The masks sit under every security layer, so each of them has to read
// its ClientHello through the chain.

func TestInboundVless_FinalMask_Reality(t *testing.T) {
	inboundOptions := inbound.VlessOption{
		RealityConfig: inbound.RealityConfig{
			Dest:        net.JoinHostPort(realityDest, "443"),
			PrivateKey:  realityPrivateKey,
			ShortID:     []string{realityShortid},
			ServerNames: []string{realityDest},
		},
		FinalMask: finalMaskChain(),
	}
	outboundOptions := outbound.VlessOption{
		TLS:               true,
		ServerName:        realityDest,
		RealityOpts:       outbound.RealityOptions{PublicKey: realityPublickey, ShortID: realityShortid},
		ClientFingerprint: "chrome",
		FinalMask:         finalMaskOutbound(),
	}
	testInboundVless(t, inboundOptions, outboundOptions)
	t.Run("xtls-rprx-vision", func(t *testing.T) {
		outboundOptions := outboundOptions
		outboundOptions.Flow = "xtls-rprx-vision"
		testInboundVless(t, inboundOptions, outboundOptions)
	})
}

func TestInboundVless_FinalMask_ShadowTLS(t *testing.T) {
	const password = "shadow-tls-password"
	inboundOptions := inbound.VlessOption{
		ShadowTLS: inbound.ShadowTLS{
			Enable:    true,
			Version:   3,
			Users:     []inbound.ShadowTLSUser{{Name: "test", Password: password}},
			Handshake: inbound.ShadowTLSHandshakeOptions{Dest: net.JoinHostPort(realityDest, "443")},
		},
		FinalMask: finalMaskChain(),
	}
	outboundOptions := outbound.VlessOption{
		TLS:           true,
		ServerName:    realityDest,
		Fingerprint:   tlsFingerprint,
		ShadowTLSOpts: outbound.ShadowTLSOptions{Password: password, Version: 3},
		FinalMask:     finalMaskOutbound(),
	}
	testInboundVlessUTLS(t, inboundOptions, outboundOptions)
}

func TestInboundVless_FinalMask_Restls(t *testing.T) {
	const password = "restls-password"
	inboundOptions := inbound.VlessOption{
		ResTLS: inbound.ResTLS{
			Enable:   true,
			Dest:     net.JoinHostPort(realityDest, "443"),
			Password: password,
		},
		FinalMask: finalMaskChain(),
	}
	outboundOptions := outbound.VlessOption{
		TLS:         true,
		ServerName:  realityDest,
		Fingerprint: tlsFingerprint,
		RestlsOpts:  outbound.RestlsOptions{Password: password, VersionHint: "tls13"},
		FinalMask:   finalMaskOutbound(),
	}
	testInboundVlessUTLS(t, inboundOptions, outboundOptions)
}

func TestInboundVless_FinalMask_JLS(t *testing.T) {
	const username = "jls-user"
	const password = "jls-password"
	inboundOptions := inbound.VlessOption{
		JLSConfig: inbound.JLSConfig{
			Enable: true,
			Users:  []inbound.JLSUser{{Username: username, Password: password}},
			SNI:    realityDest,
			Dest:   net.JoinHostPort(realityDest, "443"),
		},
		FinalMask: finalMaskChain(),
	}
	outboundOptions := outbound.VlessOption{
		TLS:        true,
		ServerName: realityDest,
		JLSOpts:    outbound.JLSOptions{Username: username, Password: password},
		FinalMask:  finalMaskOutbound(),
	}
	testInboundVlessUTLS(t, inboundOptions, outboundOptions)
}

func TestInboundTrojan_FinalMask_Reality(t *testing.T) {
	inboundOptions := inbound.TrojanOption{
		RealityConfig: inbound.RealityConfig{
			Dest:        net.JoinHostPort(realityDest, "443"),
			PrivateKey:  realityPrivateKey,
			ShortID:     []string{realityShortid},
			ServerNames: []string{realityDest},
		},
		FinalMask: finalMaskChain(),
	}
	outboundOptions := outbound.TrojanOption{
		SNI:               realityDest,
		RealityOpts:       outbound.RealityOptions{PublicKey: realityPublickey, ShortID: realityShortid},
		ClientFingerprint: "chrome",
		FinalMask:         finalMaskOutbound(),
	}
	testInboundTrojan(t, inboundOptions, outboundOptions)
}
