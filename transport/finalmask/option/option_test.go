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

// The compact resolver spelling of the first Xray xdns builds the mask too.
func TestXDNSCompactResolvers(t *testing.T) {
	fm, err := (&Option{UDP: []map[string]any{
		{"type": "xdns", "resolvers": []any{"t.example.com:aaaa+udp://1.1.1.1:53", "t.example.com:aaaa+udp://8.8.8.8"}},
	}}).Parse()
	require.NoError(t, err)
	require.True(t, fm.HasUDP())
	_, err = (&Option{UDP: []map[string]any{
		{"type": "xdns", "resolvers": []any{"t.example.com+quic://1.1.1.1"}},
	}}).Parse()
	require.Error(t, err)
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

// Xray writes the mask settings in camelCase; they decode like the
// kebab-case of the YAML, nested maps and lists included.
func TestXrayCamelCaseKeys(t *testing.T) {
	require.Equal(t, "rand-range", kebabKey("randRange"))
	require.Equal(t, "remote-ips", kebabKey("remoteIPs"))
	require.Equal(t, "textures-value", kebabKey("texturesValue"))
	require.Equal(t, "edns0", kebabKey("edns0"))
	require.Equal(t, "padding-min", kebabKey("padding-min"))
	require.Equal(t, "custom_tables", kebabKey("custom_tables"))
	require.Equal(t, "u64", kebabKey("u64"))

	fm, err := (&Option{
		TCP: []map[string]any{
			{"type": "fragment", "settings": map[string]any{"packets": "tlshello", "length": "10-20", "delay": float64(0), "maxSplit": "3-5"}},
			{"type": "header-custom", "settings": map[string]any{
				"clients": []any{[]any{map[string]any{"type": "str", "packet": "GET / HTTP/1.1\r\nX: "}, map[string]any{"rand": float64(8), "randRange": "97-122", "capture": "n"}}},
				"servers": []any{[]any{map[string]any{"reuse": "n"}}},
			}},
			{"type": "sudoku", "settings": map[string]any{"password": "p", "customTables": []any{"xpxvvpvv"}, "paddingMin": float64(10), "paddingMax": float64(30)}},
			{"type": "xmc", "settings": map[string]any{
				"password": "p", "hostname": "mc.example.com",
				"profiles": []any{map[string]any{"username": "Steve", "uuid": "069a79f4-44e9-4726-a5be-fca90e38aaf5", "texturesValue": "v", "texturesSignature": "s"}},
			}},
		},
		UDP: []map[string]any{
			{"type": "noise", "settings": map[string]any{"noise": []any{map[string]any{"rand": "10-20", "randRange": "0-255"}}}},
			{"type": "xdns", "settings": map[string]any{
				"domains":   []any{map[string]any{"names": []any{"t.example.com"}, "lenLimit": float64(200), "labelLimit": float64(60)}},
				"resolvers": []any{map[string]any{"addrs": []any{"1.1.1.1"}, "types": []any{float64(1)}, "edns0": float64(4096)}},
				"extraPoll": float64(2),
			}},
		},
	}).Parse()
	require.NoError(t, err)
	require.True(t, fm.HasTCP())
	require.True(t, fm.HasUDP())

	fm, err = (&Option{UDP: []map[string]any{
		{"type": "udphop", "settings": map[string]any{"mode": "intervalLocal", "interval": "10-20", "remoteIPs": []any{"10.0.0.1"}, "remotePorts": []any{"443", "20000-30000"}}},
	}}).Parse()
	require.NoError(t, err)
	require.True(t, fm.HasUDP())
}
