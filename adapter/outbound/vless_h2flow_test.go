package outbound

import (
	"testing"

	"github.com/metacubex/mihomo/transport/xhttp"
)

func TestXHTTPOptionsH2Flow(t *testing.T) {
	on, off := true, false
	for _, tc := range []struct {
		name    string
		opts    XHTTPOptions
		enabled *bool
		window  int
	}{
		{"unset", XHTTPOptions{}, nil, 0},
		{"h2-flow-control", XHTTPOptions{H2FlowControl: true}, &on, 0},
		{"h2-flow", XHTTPOptions{H2Flow: &xhttp.H2FlowOptions{Enabled: &on}}, &on, 0},
		{"h2-flow wins", XHTTPOptions{H2FlowControl: true, H2Flow: &xhttp.H2FlowOptions{Enabled: &off}}, &off, 0},
		{"windows keep", XHTTPOptions{H2FlowControl: true, H2Flow: &xhttp.H2FlowOptions{MaxStreamReceiveWindow: 1 << 20}}, &on, 1 << 20},
		{"windows only", XHTTPOptions{H2Flow: &xhttp.H2FlowOptions{MaxStreamReceiveWindow: 1 << 20}}, nil, 1 << 20},
	} {
		got := tc.opts.h2Flow()
		var enabled *bool
		window := 0
		if got != nil {
			enabled, window = got.Enabled, got.MaxStreamReceiveWindow
		}
		if (enabled == nil) != (tc.enabled == nil) || (enabled != nil && *enabled != *tc.enabled) || window != tc.window {
			t.Errorf("%s: got enabled %v window %d", tc.name, enabled, window)
		}
	}
}
