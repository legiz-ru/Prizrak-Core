package inbound_test

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"testing"

	"github.com/metacubex/mihomo/listener/inbound"
	"github.com/metacubex/mihomo/transport/finalmask/option"

	utls "github.com/metacubex/utls"
	"github.com/stretchr/testify/require"
)

// The Xray-core fork as the client with finalmask on its outbound, a
// Prizrak-Core vless or trojan inbound with the same masks as the server:
//
//	XRAY_BINARY=/path/to/xray go test ./listener/inbound/ -run TestFinalMaskXrayClientToMihomoServer -v

const finalMaskXrayUUID = "c2a4f3e1-7b8d-4c5e-9f01-2a3b4c5d6e7f"

// finalMaskInteropPair is one mask set written for Xray's JSON and for the
// listener's config.
type finalMaskInteropPair struct {
	name string
	xray []any
	core []map[string]any
}

func finalMaskInteropPairs() []finalMaskInteropPair {
	profileXray := map[string]any{
		"username": "Steve_01", "uuid": "069a79f4-44e9-4726-a5be-fca90e38aaf5",
		"texturesValue": strings.Repeat("texture-value-", 40), "texturesSignature": strings.Repeat("texture-signature-", 24),
	}
	profileCore := map[string]any{
		"username": "Steve_01", "uuid": "069a79f4-44e9-4726-a5be-fca90e38aaf5",
		"textures-value": strings.Repeat("texture-value-", 40), "textures-signature": strings.Repeat("texture-signature-", 24),
	}
	return []finalMaskInteropPair{
		{
			name: "fragment",
			xray: []any{map[string]any{"type": "fragment", "settings": map[string]any{"packets": "1-3", "length": "10-30", "delay": "0-1"}}},
			core: []map[string]any{{"type": "fragment", "packets": "1-3", "length": "10-30", "delay": "0-1"}},
		},
		{
			name: "header-custom",
			xray: []any{map[string]any{"type": "header-custom", "settings": map[string]any{
				"clients": []any{[]any{map[string]any{"type": "str", "packet": "GET /api HTTP/1.1\r\nX-Nonce: "}, map[string]any{"rand": 8, "randRange": "97-122", "capture": "nonce"}, map[string]any{"type": "str", "packet": "\r\n\r\n"}}},
				"servers": []any{[]any{map[string]any{"type": "str", "packet": "HTTP/1.1 101\r\nX-Nonce: "}, map[string]any{"reuse": "nonce"}, map[string]any{"type": "str", "packet": "\r\n\r\n"}}},
			}}},
			core: []map[string]any{{"type": "header-custom",
				"clients": []any{[]any{map[string]any{"type": "str", "packet": "GET /api HTTP/1.1\r\nX-Nonce: "}, map[string]any{"rand": 8, "rand-range": "97-122", "capture": "nonce"}, map[string]any{"type": "str", "packet": "\r\n\r\n"}}},
				"servers": []any{[]any{map[string]any{"type": "str", "packet": "HTTP/1.1 101\r\nX-Nonce: "}, map[string]any{"reuse": "nonce"}, map[string]any{"type": "str", "packet": "\r\n\r\n"}}},
				"errors":  []any{[]any{map[string]any{"type": "str", "packet": "HTTP/1.1 404 Not Found\r\n\r\n"}}},
			}},
		},
		{
			name: "sudoku",
			xray: []any{map[string]any{"type": "sudoku", "settings": map[string]any{"password": "sudoku-pass", "customTables": []any{"xpxvvpvv", "vxpvxvvp"}, "paddingMin": 20, "paddingMax": 40}}},
			core: []map[string]any{{"type": "sudoku", "password": "sudoku-pass", "custom-tables": []any{"xpxvvpvv", "vxpvxvvp"}, "padding-min": 20, "padding-max": 40}},
		},
		{
			name: "sudoku-ascii",
			xray: []any{map[string]any{"type": "sudoku", "settings": map[string]any{"password": "sudoku-pass", "ascii": "prefer_ascii"}}},
			core: []map[string]any{{"type": "sudoku", "password": "sudoku-pass", "ascii": "prefer_ascii"}},
		},
		{
			name: "xmc",
			xray: []any{map[string]any{"type": "xmc", "settings": map[string]any{"password": "mc-pass", "hostname": "mc.example.com", "profiles": []any{profileXray}}}},
			core: []map[string]any{{"type": "xmc", "password": "mc-pass", "hostname": "mc.example.com", "profiles": []any{profileCore}}},
		},
		{
			name: "chain",
			xray: []any{
				map[string]any{"type": "header-custom", "settings": map[string]any{
					"clients": []any{[]any{map[string]any{"type": "str", "packet": "hello"}}},
					"servers": []any{[]any{map[string]any{"type": "str", "packet": "world"}}},
				}},
				map[string]any{"type": "sudoku", "settings": map[string]any{"password": "chain"}},
				map[string]any{"type": "fragment", "settings": map[string]any{"packets": "1-2", "length": "10-20"}},
			},
			core: []map[string]any{
				{"type": "header-custom",
					"clients": []any{[]any{map[string]any{"type": "str", "packet": "hello"}}},
					"servers": []any{[]any{map[string]any{"type": "str", "packet": "world"}}},
				},
				{"type": "sudoku", "password": "chain"},
				{"type": "fragment", "packets": "1-2", "length": "10-20"},
			},
		},
	}
}

func finalMaskXrayClientConfig(t *testing.T, proto string, listenPort, serverPort int, targetAddr string, masks []any, network string) []byte {
	t.Helper()
	targetHost, targetPort, err := net.SplitHostPort(targetAddr)
	require.NoError(t, err)
	targetPortNumber, err := net.LookupPort("tcp", targetPort)
	require.NoError(t, err)
	var settings map[string]any
	switch proto {
	case "vless":
		settings = map[string]any{"vnext": []any{map[string]any{
			"address": "127.0.0.1", "port": serverPort,
			"users": []any{map[string]any{"id": finalMaskXrayUUID, "encryption": "none"}},
		}}}
	case "trojan":
		settings = map[string]any{"servers": []any{map[string]any{
			"address": "127.0.0.1", "port": serverPort, "password": finalMaskXrayUUID,
		}}}
	}
	stream := map[string]any{
		"network":   network,
		"security":  "none",
		"finalmask": map[string]any{"tcp": masks},
	}
	switch network {
	case "ws":
		stream["wsSettings"] = map[string]any{"path": "/ws"}
	case "grpc":
		stream["grpcSettings"] = map[string]any{"serviceName": "svc"}
	}
	config := map[string]any{
		"log": map[string]any{"loglevel": "debug"},
		"inbounds": []any{map[string]any{
			"listen": "127.0.0.1", "port": listenPort, "protocol": "dokodemo-door",
			"settings": map[string]any{"address": targetHost, "port": targetPortNumber, "network": "tcp"},
		}},
		"outbounds": []any{map[string]any{"protocol": proto, "settings": settings, "streamSettings": stream}},
	}
	data, err := json.MarshalIndent(config, "", "  ")
	require.NoError(t, err)
	return append(data, '\n')
}

func TestFinalMaskXrayClientToMihomoServer(t *testing.T) {
	xrayBinary := os.Getenv("XRAY_BINARY")
	if xrayBinary == "" {
		xrayBinary = os.Getenv("XRAY_BIN")
	}
	if xrayBinary == "" {
		t.Skip("XRAY_BINARY is not set; point it at the Xray-core fork's executable")
	}
	echoAddr := startVMessInteropEcho(t)

	type transport struct {
		proto, network string
	}
	for _, tr := range []transport{{"vless", "tcp"}, {"trojan", "tcp"}, {"vless", "ws"}, {"vless", "grpc"}} {
		pairs := finalMaskInteropPairs()
		if tr.network != "tcp" || tr.proto != "vless" {
			pairs = pairs[len(pairs)-1:]
		}
		for _, pair := range pairs {
			tr, pair := tr, pair
			t.Run(tr.proto+"-"+tr.network+"/"+pair.name, func(t *testing.T) {
				masks := option.Option{TCP: pair.core}
				var mihomoPort int
				switch tr.proto {
				case "vless":
					o := &inbound.VlessOption{
						BaseOption:    inbound.BaseOption{NameStr: "vless_finalmask_xray", Listen: "127.0.0.1", Port: "0"},
						Users:         []inbound.VlessUser{{Username: "xray", UUID: finalMaskXrayUUID}},
						AllowInsecure: true,
						FinalMask:     masks,
					}
					switch tr.network {
					case "ws":
						o.WsPath = "/ws"
					case "grpc":
						o.GrpcServiceName = "svc"
					}
					l, err := inbound.NewVless(o)
					require.NoError(t, err)
					require.NoError(t, l.Listen(vmessInteropDirectTunnel(t)))
					t.Cleanup(func() { _ = l.Close() })
					addr, err := netip.ParseAddrPort(l.Address())
					require.NoError(t, err)
					mihomoPort = int(addr.Port())
				case "trojan":
					l, err := inbound.NewTrojan(&inbound.TrojanOption{
						BaseOption:    inbound.BaseOption{NameStr: "trojan_finalmask_xray", Listen: "127.0.0.1", Port: "0"},
						Users:         []inbound.TrojanUser{{Username: "xray", Password: finalMaskXrayUUID}},
						AllowInsecure: true,
						FinalMask:     masks,
					})
					require.NoError(t, err)
					require.NoError(t, l.Listen(vmessInteropDirectTunnel(t)))
					t.Cleanup(func() { _ = l.Close() })
					addr, err := netip.ParseAddrPort(l.Address())
					require.NoError(t, err)
					mihomoPort = int(addr.Port())
				}

				xrayPort := vmessInteropReserveTCPPort(t)
				config := finalMaskXrayClientConfig(t, tr.proto, xrayPort.Port(), mihomoPort, echoAddr, pair.xray, tr.network)
				startXrayRealityServer(t, xrayBinary, config, xrayPort)

				vmessInteropRoundTripWithRetry(t, func() (net.Conn, error) {
					return net.Dial("tcp", net.JoinHostPort("127.0.0.1", fmt.Sprint(xrayPort.Port())))
				}, 128*1024)
			})
		}
	}
}

// The Xray fork as a REALITY client behind the chain, a Prizrak-Core REALITY
// inbound with the same chain: the masks must carry REALITY's ClientHello.
func TestFinalMaskXrayRealityClientToMihomoServer(t *testing.T) {
	xrayBinary := os.Getenv("XRAY_BINARY")
	if xrayBinary == "" {
		xrayBinary = os.Getenv("XRAY_BIN")
	}
	if xrayBinary == "" {
		t.Skip("XRAY_BINARY is not set; point it at the Xray-core fork's executable")
	}
	origin := startTLSMirrorInteropCarrierTLS(t, padRealityCarrierCertificate)
	echoAddr := startVMessInteropEcho(t)
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	mldsa65Seed := make([]byte, 32)
	mldsa65Seed[0] = 3
	_, mldsa65Verify, err := utls.RealityMldsa65KeyFromSeed(mldsa65Seed)
	require.NoError(t, err)

	pairs := finalMaskInteropPairs()
	chain := pairs[len(pairs)-1]
	in, err := inbound.NewVless(&inbound.VlessOption{
		BaseOption: inbound.BaseOption{NameStr: "vless_reality_finalmask_xray", Listen: "127.0.0.1", Port: "0"},
		Users:      []inbound.VlessUser{{Username: "xray", UUID: xrayRealityPlainUUID}},
		RealityConfig: inbound.RealityConfig{
			Dest:        origin.addr,
			PrivateKey:  base64.RawURLEncoding.EncodeToString(privateKey.Bytes()),
			ShortID:     []string{xrayRealityShortID},
			ServerNames: []string{"localhost"},
			Mldsa65Seed: base64.RawURLEncoding.EncodeToString(mldsa65Seed),
		},
		FinalMask: option.Option{TCP: chain.core},
	})
	require.NoError(t, err)
	require.NoError(t, in.Listen(vmessInteropDirectTunnel(t)))
	t.Cleanup(func() { _ = in.Close() })
	mihomoAddr, err := netip.ParseAddrPort(in.Address())
	require.NoError(t, err)

	xrayPort := vmessInteropReserveTCPPort(t)
	config := xrayRealityClientConfig(t, xrayPort.Port(), int(mihomoAddr.Port()), echoAddr, privateKey.PublicKey().Bytes(), mldsa65Verify)
	var parsed map[string]any
	require.NoError(t, json.Unmarshal(config, &parsed))
	stream := parsed["outbounds"].([]any)[0].(map[string]any)["streamSettings"].(map[string]any)
	stream["finalmask"] = map[string]any{"tcp": chain.xray}
	config, err = json.MarshalIndent(parsed, "", "  ")
	require.NoError(t, err)
	startXrayRealityServer(t, xrayBinary, config, xrayPort)

	vmessInteropRoundTripWithRetry(t, func() (net.Conn, error) {
		return net.Dial("tcp", net.JoinHostPort("127.0.0.1", fmt.Sprint(xrayPort.Port())))
	}, 128*1024)

	// A client whose chain differs in one mask must not get through: that
	// is how the round trip above proves REALITY ran over the masks.
	t.Run("mismatch", func(t *testing.T) {
		badChain := make([]any, len(chain.xray))
		copy(badChain, chain.xray)
		badChain[1] = map[string]any{"type": "sudoku", "settings": map[string]any{"password": "other"}}
		stream["finalmask"] = map[string]any{"tcp": badChain}
		config, err := json.MarshalIndent(parsed, "", "  ")
		require.NoError(t, err)
		badPort := vmessInteropReserveTCPPort(t)
		parsed["inbounds"].([]any)[0].(map[string]any)["port"] = badPort.Port()
		config, err = json.MarshalIndent(parsed, "", "  ")
		require.NoError(t, err)
		startXrayRealityServer(t, xrayBinary, config, badPort)
		conn, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", fmt.Sprint(badPort.Port())))
		require.NoError(t, err)
		require.Error(t, vmessInteropRoundTripConn(conn, 4096))
	})
}
