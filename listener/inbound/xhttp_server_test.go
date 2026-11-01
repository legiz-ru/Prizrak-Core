package inbound_test

import (
	"bufio"
	"context"
	"net"
	"net/http"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter/outbound"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener/inbound"
	"github.com/metacubex/mihomo/transport/xhttp"
	"github.com/stretchr/testify/assert"
)

func xhttpGovernedServer() *xhttp.H2FlowServerOptions {
	enabled := true
	return &xhttp.H2FlowServerOptions{Enabled: &enabled}
}

// A server with the governor's server role and h2-params serves our client
// with and without a governor of its own, over TLS and REALITY.
func TestInboundVless_XHTTP_ServerGovernor(t *testing.T) {
	for _, mode := range []string{"auto", "stream-one", "stream-up", "packet-up"} {
		mode := mode
		for _, clientGoverned := range []bool{false, true} {
			clientGoverned := clientGoverned
			name := mode + "/client-stock"
			if clientGoverned {
				name = mode + "/client-governed"
			}
			t.Run(name, func(t *testing.T) {
				xhttpOpts := func() outbound.XHTTPOptions {
					opts := outbound.XHTTPOptions{Path: "/vless-xhttp", Host: "example.com", Mode: mode}
					if clientGoverned {
						enabled := true
						opts.H2Flow = &xhttp.H2FlowOptions{Enabled: &enabled}
					}
					return opts
				}
				serverConfig := inbound.XHTTPConfig{
					Path:     "/vless-xhttp",
					Host:     "example.com",
					Mode:     mode,
					H2Flow:   xhttpGovernedServer(),
					H2Params: &xhttp.H2Params{MaxConcurrentStreams: 128, SendPingTimeout: "30s"},
				}
				t.Run("tls", func(t *testing.T) {
					testInboundVless_XHTTP(t, func() (inbound.VlessOption, outbound.VlessOption) {
						return inbound.VlessOption{
								Certificate: tlsCertificate,
								PrivateKey:  tlsPrivateKey,
								XHTTPConfig: serverConfig,
							}, outbound.VlessOption{
								TLS:               true,
								Fingerprint:       tlsFingerprint,
								ServerName:        "example.org",
								ClientFingerprint: "chrome",
								Network:           "xhttp",
								XHTTPOpts:         xhttpOpts(),
							}
					}, mode)
				})
				t.Run("reality", func(t *testing.T) {
					testInboundVless_XHTTP_Reality(t, func() (inbound.VlessOption, outbound.VlessOption) {
						return inbound.VlessOption{
								RealityConfig: inbound.RealityConfig{
									Dest:        net.JoinHostPort(realityDest, "443"),
									PrivateKey:  realityPrivateKey,
									ShortID:     []string{realityShortid},
									ServerNames: []string{realityDest},
								},
								XHTTPConfig: serverConfig,
							}, outbound.VlessOption{
								TLS:               true,
								ServerName:        realityDest,
								RealityOpts:       outbound.RealityOptions{PublicKey: realityPublickey, ShortID: realityShortid},
								ClientFingerprint: "chrome",
								Network:           "xhttp",
								XHTTPOpts:         xhttpOpts(),
							}
					}, mode)
				})
			})
		}
	}
}

func TestInboundVless_XHTTP_ServerOptionsRefused(t *testing.T) {
	for name, config := range map[string]inbound.XHTTPConfig{
		"streams above the governor": {Path: "/x", H2Flow: xhttpGovernedServer(), H2Params: &xhttp.H2Params{MaxConcurrentStreams: 5000}},
		"send window":                {Path: "/x", H2Flow: &xhttp.H2FlowServerOptions{Enabled: xhttpGovernedServer().Enabled, MaxConnectionSendWindow: 100}},
		"receive window":             {Path: "/x", H2Flow: &xhttp.H2FlowServerOptions{MaxStreamReceiveWindow: 1 << 31}},
		"ping timeout":               {Path: "/x", H2Params: &xhttp.H2Params{PingTimeout: "soon"}},
		"keep-alive range":           {Path: "/x", MuxKeepAliveSecs: "25-20"},
	} {
		config := config
		t.Run(name, func(t *testing.T) {
			options := inbound.VlessOption{
				BaseOption:  inbound.BaseOption{NameStr: "vless_inbound", Listen: "127.0.0.1", Port: "0"},
				Users:       []inbound.VlessUser{{Username: "test", UUID: userUUID}},
				Certificate: tlsCertificate,
				PrivateKey:  tlsPrivateKey,
				XHTTPConfig: config,
			}
			in, err := inbound.NewVless(&options)
			if !assert.NoError(t, err) {
				return
			}
			tunnel := NewHttpTestTunnel()
			defer tunnel.Close()
			err = in.Listen(tunnel)
			if err == nil {
				_ = in.Close()
			}
			assert.Error(t, err)
		})
	}
}

type countingDialer struct {
	C.Dialer
	read atomic.Int64
}

func (d *countingDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	conn, err := d.Dialer.DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	return &countingConn{Conn: conn, read: &d.read}, nil
}

type countingConn struct {
	net.Conn
	read *atomic.Int64
}

func (c *countingConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	c.read.Add(int64(n))
	return n, err
}

// With mux-keep-alive-secs the server pokes an idle packet-up or stream-up
// downlink that carries Mux.Cool; stream-one and servers without the option
// stay silent.
func TestInboundVless_XHTTP_MuxKeepAlive(t *testing.T) {
	for _, tc := range []struct {
		mode      string
		keepAlive string
		poked     bool
	}{
		{"packet-up", "1", true},
		{"stream-up", "1", true},
		{"stream-one", "1", false},
		{"packet-up", "", false},
	} {
		tc := tc
		t.Run(tc.mode+"/"+tc.keepAlive, func(t *testing.T) {
			t.Parallel()
			inboundOptions := inbound.VlessOption{
				BaseOption:  inbound.BaseOption{NameStr: "vless_inbound", Listen: "127.0.0.1", Port: "0"},
				Users:       []inbound.VlessUser{{Username: "test", UUID: userUUID}},
				Certificate: tlsCertificate,
				PrivateKey:  tlsPrivateKey,
				XHTTPConfig: inbound.XHTTPConfig{
					Path:              "/vless-xhttp",
					Host:              "example.com",
					Mode:              tc.mode,
					MuxKeepAliveSecs:  tc.keepAlive,
					MuxKeepAliveBytes: "8-16",
				},
			}
			in, err := inbound.NewVless(&inboundOptions)
			if !assert.NoError(t, err) {
				return
			}
			tunnel := NewHttpTestTunnel()
			defer tunnel.Close()
			if !assert.NoError(t, in.Listen(tunnel)) {
				return
			}
			defer in.Close()
			addrPort, err := netip.ParseAddrPort(in.Address())
			if !assert.NoError(t, err) {
				return
			}

			dialer := &countingDialer{Dialer: tunnel.NewDialer()}
			outboundOptions := outbound.VlessOption{
				Server:            addrPort.Addr().String(),
				Port:              int(addrPort.Port()),
				UUID:              userUUID,
				TLS:               true,
				Fingerprint:       tlsFingerprint,
				ServerName:        "example.org",
				ClientFingerprint: "chrome",
				Network:           "xhttp",
				XHTTPOpts:         outbound.XHTTPOptions{Path: "/vless-xhttp", Host: "example.com", Mode: tc.mode},
			}
			outboundOptions.Name = "vless_outbound"
			outboundOptions.DialerForAPI = dialer
			outboundOptions.TunnelForAPI = tunnel
			out, err := outbound.NewVless(outboundOptions)
			if !assert.NoError(t, err) {
				return
			}
			defer out.Close()
			muxCool, err := outbound.NewMuxCool(outbound.MuxCoolOption{Enabled: true}, out)
			if !assert.NoError(t, err) {
				return
			}
			defer muxCool.Close()

			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			conn, err := muxCool.DialContext(ctx, &C.Metadata{NetWork: C.TCP, DstIP: remoteAddr, DstPort: 80})
			if !assert.NoError(t, err) {
				return
			}
			defer conn.Close()
			// One request opens the session; the connection then stays idle.
			_, err = conn.Write([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))
			if !assert.NoError(t, err) {
				return
			}
			resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
			if !assert.NoError(t, err) {
				return
			}
			_ = resp.Body.Close()

			before := dialer.read.Load()
			time.Sleep(3500 * time.Millisecond)
			silent := dialer.read.Load() - before
			if tc.poked {
				assert.Greater(t, silent, int64(0), "an idle downlink must be poked")
			} else {
				assert.Zero(t, silent, "the downlink must stay silent")
			}
		})
	}
}
