package xhttp

import (
	"github.com/metacubex/mihomo/log"

	"github.com/metacubex/http"
)

// H2FlowOptions is the "h2-flow" block of a proxy's xhttp-opts, the
// counterpart of "h2Flow" in xhttpSettings.extra of Medium1992/Xray-core-fork
// (ported from Medium1992/mihomo-proxy-ros 20740fa):
//
//	xhttp-opts:
//	  h2-flow:
//	    enabled: true
//	    max-stream-receive-window: 16777216
//	    max-connection-receive-window: 33554432
//
// enabled turns the flow governor on for this proxy; unset or false, it is
// off. The windows are what this client grants for downloads, from 65535
// bytes to 1 GiB; unset, Go's 4 MiB per stream. With the governor they are a
// ceiling and the real window follows what is read; without it they are fixed
// windows. Only the HTTP/2 mode uses the block.
type H2FlowOptions struct {
	Enabled                    *bool `proxy:"enabled,omitempty"`
	MaxStreamReceiveWindow     int   `proxy:"max-stream-receive-window,omitempty"`
	MaxConnectionReceiveWindow int   `proxy:"max-connection-receive-window,omitempty"`
}

func (o *H2FlowOptions) governed() bool {
	return o != nil && o.Enabled != nil && *o.Enabled
}

func h2FlowReceiveWindow(v int, name string) int {
	if v == 0 {
		return 0
	}
	if v < h2InitWindow || v > 1<<30 {
		log.Warnln("[XHTTP] h2-flow.%s=%d is outside 65535..1073741824, ignored", name, v)
		return 0
	}
	return v
}

// apply puts the receive windows on cfg.
func (o *H2FlowOptions) apply(cfg *http.HTTP2Config) {
	if o == nil {
		return
	}
	if v := h2FlowReceiveWindow(o.MaxStreamReceiveWindow, "max-stream-receive-window"); v != 0 {
		cfg.MaxReceiveBufferPerStream = v
	}
	if v := h2FlowReceiveWindow(o.MaxConnectionReceiveWindow, "max-connection-receive-window"); v != 0 {
		cfg.MaxReceiveBufferPerConnection = v
	}
}
