package xhttp

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/metacubex/http"
	"github.com/metacubex/tls"
)

// H2FlowServerOptions is the "h2-flow" block of an inbound's xhttp-config,
// the server role of the flow governor, as "h2Flow" in xhttpSettings of
// Jolymmiles/Xray-core:
//
//	xhttp-config:
//	  h2-flow:
//	    enabled: true
//	    max-stream-receive-window: 6291456
//	    max-connection-receive-window: 6291456
//	    max-connection-send-window: 4194304
//	    queue-cuts: true
//
// enabled turns the governor on for this inbound's HTTP/2 connections; unset
// or false, the HTTP/2 wiring is stock. The receive windows are what the
// server grants for uploads, from 65535 bytes to 1 GiB; unset, a governed
// server grants 6 MiB and an ungoverned one Go's 1 MiB. With the governor
// they are a ceiling and the real window follows what is read; without it
// they are fixed windows. max-connection-send-window bounds what one
// connection's client may hold of the server's data, unread or as open
// window: unset or 0 means 4 MiB, -1 lifts the limit, otherwise 65535 to
// 1 GiB. queue-cuts, on by default, lets the governor cut download caps
// against a queue on the path; false leaves that queue alone.
type H2FlowServerOptions struct {
	Enabled                    *bool `inbound:"enabled,omitempty" json:"enabled,omitempty"`
	MaxStreamReceiveWindow     int   `inbound:"max-stream-receive-window,omitempty" json:"max-stream-receive-window,omitempty"`
	MaxConnectionReceiveWindow int   `inbound:"max-connection-receive-window,omitempty" json:"max-connection-receive-window,omitempty"`
	MaxConnectionSendWindow    int   `inbound:"max-connection-send-window,omitempty" json:"max-connection-send-window,omitempty"`
	QueueCuts                  *bool `inbound:"queue-cuts,omitempty" json:"queue-cuts,omitempty"`
}

// flowServerReceiveWindow is what a governed server grants for uploads unless
// configured otherwise: the most Linux autotuning lets one TCP socket buffer
// (tcp_rmem). Go's own 1 MiB per connection caps every upload on it at
// 1 MiB per round trip; the governor still holds the window to what is read.
const flowServerReceiveWindow = 6 << 20

// flowServerSendWindow is what a governed server lets one connection's client
// hold of its data unless configured otherwise: the window a Go client grants
// one stream.
const flowServerSendWindow = 4 << 20

func (o *H2FlowServerOptions) governed() bool {
	return o != nil && o.Enabled != nil && *o.Enabled
}

func (o *H2FlowServerOptions) sendWindow() (int64, error) {
	if o == nil {
		return flowServerSendWindow, nil
	}
	switch w := o.MaxConnectionSendWindow; {
	case w == -1:
		return 0, nil
	case w == 0:
		return flowServerSendWindow, nil
	case w < h2InitWindow || w > 1<<30:
		return 0, fmt.Errorf("xhttp h2-flow max-connection-send-window %d is not -1, 0 or within 65535..1073741824", w)
	default:
		return int64(w), nil
	}
}

func checkReceiveWindow(name string, v int) error {
	if v != 0 && (v < h2InitWindow || v > 1<<30) {
		return fmt.Errorf("xhttp h2-flow %s %d is outside 65535..1073741824", name, v)
	}
	return nil
}

// H2Params is the "h2-params" block of an inbound's xhttp-config: the HTTP/2
// settings of the server, as "h2Params" in Xray's xhttpSettings
// (XTLS/Xray-core#7295). Unset fields keep Go's defaults; durations take Go
// syntax ("15s") or a number of seconds.
type H2Params struct {
	MaxConcurrentStreams          int    `inbound:"max-concurrent-streams,omitempty" json:"max-concurrent-streams,omitempty"`
	StrictMaxConcurrentRequests   bool   `inbound:"strict-max-concurrent-requests,omitempty" json:"strict-max-concurrent-requests,omitempty"`
	MaxDecoderHeaderTableSize     int    `inbound:"max-decoder-header-table-size,omitempty" json:"max-decoder-header-table-size,omitempty"`
	MaxEncoderHeaderTableSize     int    `inbound:"max-encoder-header-table-size,omitempty" json:"max-encoder-header-table-size,omitempty"`
	MaxReadFrameSize              int    `inbound:"max-read-frame-size,omitempty" json:"max-read-frame-size,omitempty"`
	MaxReceiveBufferPerConnection int    `inbound:"max-receive-buffer-per-connection,omitempty" json:"max-receive-buffer-per-connection,omitempty"`
	MaxReceiveBufferPerStream     int    `inbound:"max-receive-buffer-per-stream,omitempty" json:"max-receive-buffer-per-stream,omitempty"`
	SendPingTimeout               string `inbound:"send-ping-timeout,omitempty" json:"send-ping-timeout,omitempty"`
	PingTimeout                   string `inbound:"ping-timeout,omitempty" json:"ping-timeout,omitempty"`
	WriteByteTimeout              string `inbound:"write-byte-timeout,omitempty" json:"write-byte-timeout,omitempty"`
	PermitProhibitedCipherSuites  bool   `inbound:"permit-prohibited-cipher-suites,omitempty" json:"permit-prohibited-cipher-suites,omitempty"`
}

func parseH2Duration(name, s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil
	}
	if n, err := strconv.ParseFloat(s, 64); err == nil {
		if n < 0 {
			return 0, fmt.Errorf("xhttp h2-params %s %q is negative", name, s)
		}
		return time.Duration(n * float64(time.Second)), nil
	}
	d, err := time.ParseDuration(s)
	if err != nil || d < 0 {
		return 0, fmt.Errorf("xhttp h2-params %s %q is not a duration", name, s)
	}
	return d, nil
}

func (p *H2Params) build() (*http.HTTP2Config, error) {
	if p == nil {
		return nil, nil
	}
	conf := &http.HTTP2Config{
		MaxConcurrentStreams:          p.MaxConcurrentStreams,
		StrictMaxConcurrentRequests:   p.StrictMaxConcurrentRequests,
		MaxDecoderHeaderTableSize:     p.MaxDecoderHeaderTableSize,
		MaxEncoderHeaderTableSize:     p.MaxEncoderHeaderTableSize,
		MaxReadFrameSize:              p.MaxReadFrameSize,
		MaxReceiveBufferPerConnection: p.MaxReceiveBufferPerConnection,
		MaxReceiveBufferPerStream:     p.MaxReceiveBufferPerStream,
		PermitProhibitedCipherSuites:  p.PermitProhibitedCipherSuites,
	}
	var err error
	if conf.SendPingTimeout, err = parseH2Duration("send-ping-timeout", p.SendPingTimeout); err != nil {
		return nil, err
	}
	if conf.PingTimeout, err = parseH2Duration("ping-timeout", p.PingTimeout); err != nil {
		return nil, err
	}
	if conf.WriteByteTimeout, err = parseH2Duration("write-byte-timeout", p.WriteByteTimeout); err != nil {
		return nil, err
	}
	return conf, nil
}

// ServerHTTP2Config returns the HTTP/2 settings of an XHTTP server, or nil to
// keep Go's defaults. h2-params is the base; a receive window set in h2-flow
// overrides it, and with the governor on its defaults fill a window still
// unset. A governed server must not advertise more concurrent streams than
// the governor tracks.
func ServerHTTP2Config(params *H2Params, flow *H2FlowServerOptions) (*http.HTTP2Config, error) {
	conf, err := params.build()
	if err != nil {
		return nil, err
	}
	var stream, connWindow int
	if flow != nil {
		stream, connWindow = flow.MaxStreamReceiveWindow, flow.MaxConnectionReceiveWindow
		if err := checkReceiveWindow("max-stream-receive-window", stream); err != nil {
			return nil, err
		}
		if err := checkReceiveWindow("max-connection-receive-window", connWindow); err != nil {
			return nil, err
		}
	}
	governed := flow.governed()
	if governed {
		if _, err := flow.sendWindow(); err != nil {
			return nil, err
		}
	}
	if conf == nil && stream == 0 && connWindow == 0 && !governed {
		return nil, nil
	}
	if conf == nil {
		conf = new(http.HTTP2Config)
	}
	if stream != 0 {
		conf.MaxReceiveBufferPerStream = stream
	}
	if connWindow != 0 {
		conf.MaxReceiveBufferPerConnection = connWindow
	}
	if governed {
		if conf.MaxReceiveBufferPerStream == 0 {
			conf.MaxReceiveBufferPerStream = flowServerReceiveWindow
		}
		if conf.MaxReceiveBufferPerConnection == 0 {
			conf.MaxReceiveBufferPerConnection = flowServerReceiveWindow
		}
		if conf.MaxConcurrentStreams > flowMaxStreams {
			return nil, fmt.Errorf("xhttp h2-params max-concurrent-streams %d exceeds the %d streams the h2-flow governor tracks", conf.MaxConcurrentStreams, flowMaxStreams)
		}
	}
	return conf, nil
}

// h2ConnWindow is the connection receive window net/http grants for h2: a
// value outside [65535, 2^31-1] is its default, as in its setDefault.
func h2ConnWindow(h2 *http.HTTP2Config) int32 {
	if h2 != nil && h2.MaxReceiveBufferPerConnection >= h2InitWindow && h2.MaxReceiveBufferPerConnection <= h2MaxWindow {
		return int32(h2.MaxReceiveBufferPerConnection)
	}
	return 1 << 20 // Go's default
}

// NewFlowListener puts the governor's server role over the connections l
// accepts when flow turns it on, and returns l itself otherwise. conf is the
// HTTP/2 config the server runs with, from ServerHTTP2Config. Wrap the
// listener that hands out the connections the HTTP server reads: above TLS,
// REALITY and the like.
func NewFlowListener(l net.Listener, flow *H2FlowServerOptions, conf *http.HTTP2Config) (net.Listener, error) {
	if !flow.governed() {
		return l, nil
	}
	sendWindow, err := flow.sendWindow()
	if err != nil {
		return nil, err
	}
	fl := &flowListener{
		Listener:    l,
		up:          flowDefault,
		down:        flowDefault,
		sendWindow:  sendWindow,
		noQueueCuts: flow.QueueCuts != nil && !*flow.QueueCuts,
		connWindow:  h2ConnWindow(conf),
	}
	return &flowServerListener{fl}, nil
}

// flowServerListener is flowListener for this core's TLS: it shows the HTTP
// server a connection from github.com/metacubex/tls as TLS, as flowTLSConn
// does for crypto/tls, so the server still answers plaintext probes and picks
// the protocol by ALPN.
type flowServerListener struct {
	*flowListener
}

func (l *flowServerListener) Accept() (net.Conn, error) {
	c, err := l.flowListener.Accept()
	if err != nil {
		return nil, err
	}
	if fc, ok := c.(*flowConn); ok {
		if tc, ok := fc.Conn.(*tls.Conn); ok {
			return flowServerTLSConn{flowConn: fc, tc: tc}, nil
		}
	}
	return c, nil
}

type flowServerTLSConn struct {
	*flowConn
	tc *tls.Conn
}

var _ http.TLSConn = flowServerTLSConn{}

func (c flowServerTLSConn) NetConn() net.Conn { return c.tc.NetConn() }

func (c flowServerTLSConn) ConnectionState() tls.ConnectionState { return c.tc.ConnectionState() }

func (c flowServerTLSConn) HandshakeContext(ctx context.Context) error {
	err := c.tc.HandshakeContext(ctx)
	c.followServerALPN()
	return err
}

// followServerALPN is followALPN for a github.com/metacubex/tls connection.
func (c flowServerTLSConn) followServerALPN() {
	if c.alpnDone.Load() {
		return
	}
	st := c.tc.ConnectionState()
	if !st.HandshakeComplete {
		return
	}
	if st.NegotiatedProtocol == "h2" {
		c.alpnH2.Store(true)
	} else {
		c.mode.Store(flowPlain)
	}
	c.alpnDone.Store(true)
}
