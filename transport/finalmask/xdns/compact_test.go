package xdns

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// The compact spelling of the first xdns client: the zone, the record type
// and the resolver in one string, EDNS0 4096 as that client sent it.
func TestExpandCompactResolvers(t *testing.T) {
	settings := map[string]any{
		"resolvers": []any{
			"auth.example.com:aaaa+udp://77.88.8.8:53",
			"auth.example.com:aaaa+udp://77.88.8.1:53",
			"auth.example.com:AAAA+udp://8.8.8.8:53",
		},
	}
	require.NoError(t, ExpandCompact(settings))
	require.Equal(t, []any{
		map[string]any{"names": []any{"auth.example.com"}, "edns0": int64(4096), "types": []any{int64(TypeAAAA)}},
	}, settings["domains"])
	require.Equal(t, []any{
		map[string]any{"addrs": []any{"udp://77.88.8.8:53"}},
		map[string]any{"addrs": []any{"udp://77.88.8.1:53"}},
		map[string]any{"addrs": []any{"udp://8.8.8.8:53"}},
	}, settings["resolvers"])
}

// A resolver without a method queries TXT; a domain entry without one
// keeps every type; distinct names and types each get a zone, and
// structured entries are kept next to the expanded ones.
func TestExpandCompactMixed(t *testing.T) {
	settings := map[string]any{
		"domains": []any{
			"t.example.com",
			map[string]any{"names": []any{"s.example.com"}, "types": []any{int64(16)}},
		},
		"resolvers": []any{
			"t.example.com+udp://1.1.1.1",
			"t.example.com:a+tcp://9.9.9.9:53",
			map[string]any{"addrs": []any{"udp://8.8.8.8:53"}},
		},
	}
	require.NoError(t, ExpandCompact(settings))
	require.Equal(t, []any{
		map[string]any{"names": []any{"s.example.com"}, "types": []any{int64(16)}},
		map[string]any{"names": []any{"t.example.com"}, "edns0": int64(4096)},
		map[string]any{"names": []any{"t.example.com"}, "edns0": int64(4096), "types": []any{int64(TypeTXT)}},
		map[string]any{"names": []any{"t.example.com"}, "edns0": int64(4096), "types": []any{int64(TypeA)}},
	}, settings["domains"])
	require.Equal(t, []any{
		map[string]any{"addrs": []any{"udp://1.1.1.1"}},
		map[string]any{"addrs": []any{"tcp://9.9.9.9:53"}},
		map[string]any{"addrs": []any{"udp://8.8.8.8:53"}},
	}, settings["resolvers"])
}

func TestExpandCompactLeavesStructuredSettingsAlone(t *testing.T) {
	settings := map[string]any{
		"domains":   []any{map[string]any{"names": []any{"t.example.com"}}},
		"resolvers": []any{map[string]any{"addrs": []any{"1.1.1.1"}}},
	}
	require.NoError(t, ExpandCompact(settings))
	require.Equal(t, []any{map[string]any{"names": []any{"t.example.com"}}}, settings["domains"])
	require.Equal(t, []any{map[string]any{"addrs": []any{"1.1.1.1"}}}, settings["resolvers"])
}

func TestExpandCompactRejects(t *testing.T) {
	for spec, want := range map[string]string{
		"bad://127.0.0.1:53":           "invalid resolver scheme",
		"t.example.com+quic://1.1.1.1": "unknown resolver scheme",
		"t.example.com+udp://":         "empty resolver server",
		"t.example.com:mx+udp://1.1.1": "unsupported method",
		":aaaa+udp://1.1.1.1":          "empty domain",
	} {
		err := ExpandCompact(map[string]any{"resolvers": []any{spec}})
		require.Error(t, err, spec)
		require.Contains(t, err.Error(), want, spec)
	}
	err := ExpandCompact(map[string]any{"domains": []any{"t.example.com:mx"}})
	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported method")
}

// The expanded settings build a mask like the structured spelling would.
func TestCompactBuildsTheSameConfig(t *testing.T) {
	compact := map[string]any{"resolvers": []any{"auth.example.com:aaaa+udp://77.88.8.8:53", "auth.example.com:aaaa+udp://8.8.8.8:53"}}
	require.NoError(t, ExpandCompact(compact))
	got, err := New(Option{
		Domains:   []DomainOption{{Names: []string{"auth.example.com"}, Types: []int{int(TypeAAAA)}, EDNS0: compactEDNS0}},
		Resolvers: []ResolverOption{{Addrs: []string{"udp://77.88.8.8:53"}}, {Addrs: []string{"udp://8.8.8.8:53"}}},
	})
	require.NoError(t, err)
	require.Len(t, got.Domains, 1)
	require.Equal(t, "auth.example.com", got.Domains[0].Name)
	require.Equal(t, []uint16{TypeAAAA}, got.Domains[0].Types)
	require.Equal(t, uint16(compactEDNS0), got.Domains[0].EDNS0)
	require.Len(t, got.Resolvers, 2)
	require.Equal(t, "77.88.8.8:53", got.Resolvers[0].Addr)
}
