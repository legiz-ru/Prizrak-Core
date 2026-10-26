package option

import (
	"testing"

	"github.com/metacubex/mihomo/transport/finalmask/custom"
	"github.com/metacubex/mihomo/transport/finalmask/fragment"
	"github.com/metacubex/mihomo/transport/finalmask/noise"
	"github.com/metacubex/mihomo/transport/finalmask/sudoku"
	"github.com/metacubex/mihomo/transport/finalmask/udphop"
	"github.com/metacubex/mihomo/transport/finalmask/xdns"
	"github.com/metacubex/mihomo/transport/finalmask/xicmp"

	"github.com/stretchr/testify/require"
)

func TestParse(t *testing.T) {
	var none *Option
	fm, err := none.Parse()
	require.NoError(t, err)
	require.Nil(t, fm)
	require.False(t, fm.HasTCP())
	require.False(t, fm.HasUDP())

	fm, err = (&Option{}).Parse()
	require.NoError(t, err)
	require.Nil(t, fm)

	fm, err = (&Option{
		TCP: []map[string]any{
			{"type": "fragment", "packets": "tlshello", "length": "100-200", "delay": "10-20"},
			{"type": "header-custom", "clients": []any{[]any{map[string]any{"packet": "GET / HTTP/1.1\r\n", "type": "str"}}}},
			{"type": "sudoku", "password": "p", "custom-tables": []any{"xpxvvpvv"}, "padding-min": 10, "padding-max": 30},
		},
		UDP: []map[string]any{
			{"type": "noise", "noise": []any{map[string]any{"type": "exp", "packet": "<b 0d0a> <r 16>"}}},
			{"type": "header-custom", "mode": "standalone", "client": []any{map[string]any{"rand": 4, "capture": "txid"}}, "server": []any{map[string]any{"reuse": "txid"}}},
			{"type": "sudoku", "password": "p"},
			{"type": "udphop", "mode": "intervalLocal", "interval": "10-20"},
		},
	}).Parse()
	require.NoError(t, err)
	require.True(t, fm.HasTCP())
	require.True(t, fm.HasUDP())
}

// Xray nests the mask's settings under "settings"; that spelling is accepted
// as well, so a finalmask block can be copied from an Xray config.
func TestAcceptsXraySettings(t *testing.T) {
	fm, err := (&Option{
		TCP: []map[string]any{
			{"type": "fragment", "settings": map[string]any{"packets": "tlshello", "length": "1-1", "delay": 0}},
			{"type": "xmc", "settings": map[string]any{
				"password": "p", "hostname": "mc.example.com",
				"profiles": []any{map[string]any{"username": "Steve", "uuid": "069a79f4-44e9-4726-a5be-fca90e38aaf5", "textures-value": "v", "textures-signature": "s"}},
			}},
		},
		UDP: []map[string]any{
			{"type": "xicmp", "settings": map[string]any{"dgram": true, "ips": []any{"10.0.0.1"}}},
		},
	}).Parse()
	require.NoError(t, err)
	require.True(t, fm.HasTCP())
	require.True(t, fm.HasUDP())
	// xdns must be the last UDP entry: it is the one on the wire.
	_, err = (&Option{UDP: []map[string]any{
		{"type": "xdns", "domains": []any{map[string]any{"names": []any{"t.example.com"}}}, "resolvers": []any{map[string]any{"addrs": []any{"1.1.1.1"}}}},
		{"type": "noise", "noise": []any{map[string]any{"rand": "10-20"}}},
	}}).Parse()
	require.Error(t, err)
	fm, err = (&Option{UDP: []map[string]any{
		{"type": "noise", "noise": []any{map[string]any{"rand": "10-20"}}},
		{"type": "xdns", "domains": []any{map[string]any{"names": []any{"t.example.com"}}}, "resolvers": []any{map[string]any{"addrs": []any{"1.1.1.1"}}}},
	}}).Parse()
	require.NoError(t, err)
	require.True(t, fm.HasUDP())
}

func TestRejects(t *testing.T) {
	for name, o := range map[string]*Option{
		"no type":        {TCP: []map[string]any{{"packets": "tlshello"}}},
		"unknown tcp":    {TCP: []map[string]any{{"type": "nope"}}},
		"udp as tcp":     {TCP: []map[string]any{{"type": "noise"}}},
		"tcp as udp":     {UDP: []map[string]any{{"type": "fragment"}}},
		"mkcp dropped":   {UDP: []map[string]any{{"type": "mkcp-legacy"}}},
		"salamander":     {UDP: []map[string]any{{"type": "salamander", "password": "x"}}},
		"realm":          {UDP: []map[string]any{{"type": "realm"}}},
		"bad fragment":   {TCP: []map[string]any{{"type": "fragment", "packets": "0-1", "length": "1"}}},
		"bad sudoku":     {TCP: []map[string]any{{"type": "sudoku", "custom-table": "abc"}}},
		"bad udphop":     {UDP: []map[string]any{{"type": "udphop", "mode": "intervalLocal", "interval": 1}}},
		"bad xicmp":      {UDP: []map[string]any{{"type": "xicmp", "ips": []any{"x"}}}},
		"bad settings":   {TCP: []map[string]any{{"type": "fragment", "settings": "x"}}},
		"wrong type":     {TCP: []map[string]any{{"type": "fragment", "length": []any{1}}}},
		"xmc no profile": {TCP: []map[string]any{{"type": "xmc", "password": "p"}}},
	} {
		_, err := o.Parse()
		require.Error(t, err, name)
	}
}

// The mask types stay the ones the registry hands out.
func TestRegistryTypes(t *testing.T) {
	cases := []struct {
		entry map[string]any
		want  any
		udp   bool
	}{
		{map[string]any{"type": "fragment", "length": "1"}, &fragment.Mask{}, false},
		{map[string]any{"type": "header-custom"}, &custom.TCPConfig{}, false},
		{map[string]any{"type": "sudoku"}, &sudoku.Config{}, false},
		{map[string]any{"type": "noise"}, &noise.Config{}, true},
		{map[string]any{"type": "header-custom"}, &custom.UDPConfig{}, true},
		{map[string]any{"type": "header-custom", "mode": "standalone"}, &custom.UDPStandaloneConfig{}, true},
		{map[string]any{"type": "sudoku"}, &sudoku.Config{}, true},
		{map[string]any{"type": "udphop", "mode": "intervalLocal"}, &udphop.Config{}, true},
		{map[string]any{"type": "xdns", "domains": []any{map[string]any{"names": []any{"t.example.com"}}}, "resolvers": []any{map[string]any{"addrs": []any{"1.1.1.1"}}}}, &xdns.Config{}, true},
		{map[string]any{"type": "xicmp"}, &xicmp.Config{}, true},
	}
	for _, c := range cases {
		if c.udp {
			mask, err := BuildUDPMask(c.entry)
			require.NoError(t, err, c.entry)
			require.IsType(t, c.want, mask, c.entry)
		} else {
			mask, err := BuildTCPMask(c.entry)
			require.NoError(t, err, c.entry)
			require.IsType(t, c.want, mask, c.entry)
		}
	}
}
