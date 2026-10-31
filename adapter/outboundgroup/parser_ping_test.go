package outboundgroup

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/component/pingconfig"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type task struct {
	url      string
	interval uint
}

// taskProvider records the health-check tasks groups register on it.
type taskProvider struct {
	P.ProxyProvider
	healthURL string
	tasks     []task
}

func (p *taskProvider) Name() string               { return "sub" }
func (p *taskProvider) VehicleType() P.VehicleType { return P.HTTP }
func (p *taskProvider) HealthCheckURL() string     { return p.healthURL }
func (p *taskProvider) Proxies() []C.Proxy         { return nil }
func (p *taskProvider) Version() uint32            { return 1 }
func (p *taskProvider) Touch()                     {}
func (p *taskProvider) RegisterHealthCheckTask(url string, _ utils.IntRanges[uint16], _ string, interval uint) {
	p.tasks = append(p.tasks, task{url: url, interval: interval})
}

func parseGroup(t *testing.T, mapping map[string]any, providers map[string]P.ProxyProvider) (ProxyGroup, error) {
	t.Helper()
	proxies := map[string]C.Proxy{
		"COMPATIBLE": adapter.NewProxy(outbound.NewCompatible()),
		"node":       adapter.NewProxy(outbound.NewDirect()),
	}
	if providers == nil {
		providers = map[string]P.ProxyProvider{}
	}
	return ParseProxyGroup(mapping, proxies, providers, []string{"node"}, nil)
}

func pingProfileOf(group ProxyGroup) *pingconfig.Profile {
	return group.(interface{ PingProfile() *pingconfig.Profile }).PingProfile()
}

// The block's fields left out come from the group.
func TestParseGroupPingConfigInherits(t *testing.T) {
	group, err := parseGroup(t, map[string]any{
		"name": "auto", "type": "url-test", "proxies": []any{"node"},
		"url": testUrl, "interval": 120, "timeout": 3000,
		"ping-config": map[string]any{"destination": "https://speed.cloudflare.com/__down?bytes=51200", "http-method": "GET", "sampling": 2},
	}, nil)
	require.NoError(t, err)
	profile := pingProfileOf(group)
	require.NotNil(t, profile)
	assert.Equal(t, testUrl, profile.URL)
	assert.Equal(t, "https://speed.cloudflare.com/__down?bytes=51200", profile.Destination)
	assert.Equal(t, 120*time.Second, profile.Interval)
	assert.Equal(t, 3*time.Second, profile.Timeout)
	assert.Equal(t, 2, profile.Sampling)
	assert.Equal(t, "auto", profile.Group)

	// without url the default test url is the key and the destination
	group, err = parseGroup(t, map[string]any{
		"name": "auto", "type": "fallback", "proxies": []any{"node"},
		"ping-config": map[string]any{},
	}, nil)
	require.NoError(t, err)
	profile = pingProfileOf(group)
	assert.Equal(t, C.DefaultTestURL, profile.URL)
	assert.Equal(t, C.DefaultTestURL, profile.Destination)
	assert.Equal(t, 300*time.Second, profile.Interval)
	assert.Equal(t, 5*time.Second, profile.Timeout)
}

func TestParseGroupWithoutPingConfig(t *testing.T) {
	for _, kind := range []string{"url-test", "fallback", "load-balance", "select", "smart"} {
		group, err := parseGroup(t, map[string]any{"name": "g-" + kind, "type": kind, "proxies": []any{"node"}, "url": testUrl}, nil)
		require.NoError(t, err, kind)
		assert.Nil(t, pingProfileOf(group), kind)
		if c, ok := group.(interface{ Close() error }); ok {
			_ = c.Close()
		}
	}
}

func TestParseGroupRejectsABadPingConfig(t *testing.T) {
	for _, ping := range []any{
		map[string]any{"http-method": "PUT"},
		map[string]any{"destination": "ftp://example.com"},
		map[string]any{"sampling": 99},
		"GET",
	} {
		_, err := parseGroup(t, map[string]any{
			"name": "auto", "type": "url-test", "proxies": []any{"node"}, "url": testUrl, "ping-config": ping,
		}, nil)
		assert.Error(t, err, "%v", ping)
	}
}

// A use: group with ping-config registers its url with an interval, so the
// provider's loop starts though the group sets none; a select group makes
// no background checks and registers none.
func TestParseGroupPingConfigRegistersAnInterval(t *testing.T) {
	sub := &taskProvider{}
	_, err := parseGroup(t, map[string]any{
		"name": "auto", "type": "url-test", "use": []any{"sub"}, "url": testUrl,
		"ping-config": map[string]any{"interval": "30s"},
	}, map[string]P.ProxyProvider{"sub": sub})
	require.NoError(t, err)
	assert.Equal(t, []task{{url: testUrl, interval: 300}}, sub.tasks)

	sub = &taskProvider{}
	_, err = parseGroup(t, map[string]any{
		"name": "auto", "type": "url-test", "use": []any{"sub"}, "url": testUrl, "interval": 60,
		"ping-config": map[string]any{},
	}, map[string]P.ProxyProvider{"sub": sub})
	require.NoError(t, err)
	assert.Equal(t, []task{{url: testUrl, interval: 60}}, sub.tasks)

	// without url and without the provider's own: the default url needs a task
	sub = &taskProvider{}
	group, err := parseGroup(t, map[string]any{
		"name": "auto", "type": "url-test", "use": []any{"sub"},
		"ping-config": map[string]any{},
	}, map[string]P.ProxyProvider{"sub": sub})
	require.NoError(t, err)
	assert.Equal(t, []task{{url: C.DefaultTestURL, interval: 300}}, sub.tasks)
	assert.Equal(t, C.DefaultTestURL, pingProfileOf(group).URL)

	// the provider's own health-check url is the key: it is checked already
	sub = &taskProvider{healthURL: "https://provider.test/204"}
	group, err = parseGroup(t, map[string]any{
		"name": "auto", "type": "url-test", "use": []any{"sub"},
		"ping-config": map[string]any{},
	}, map[string]P.ProxyProvider{"sub": sub})
	require.NoError(t, err)
	assert.Empty(t, sub.tasks)
	assert.Equal(t, "https://provider.test/204", pingProfileOf(group).URL)

	sub = &taskProvider{}
	_, err = parseGroup(t, map[string]any{
		"name": "manual", "type": "select", "use": []any{"sub"}, "url": testUrl,
		"ping-config": map[string]any{},
	}, map[string]P.ProxyProvider{"sub": sub})
	require.NoError(t, err)
	assert.Equal(t, []task{{url: testUrl, interval: 0}}, sub.tasks)
}

// The group JSON shows the ping-config that checks its url, and nothing
// without one; testUrl stays the plain url.
func TestGroupJSONShowsPingConfig(t *testing.T) {
	defer pingconfig.SetActive(nil)
	for _, kind := range []string{"url-test", "fallback", "load-balance", "select", "smart"} {
		pingconfig.SetActive(nil)
		group, err := parseGroup(t, map[string]any{
			"name": "g-" + kind, "type": kind, "proxies": []any{"node"}, "url": testUrl,
			"ping-config": map[string]any{"http-method": "GET", "interval": 15},
		}, nil)
		require.NoError(t, err, kind)

		body, err := json.Marshal(group)
		require.NoError(t, err, kind)
		assert.NotContains(t, string(body), "pingConfig", "%s: not applied yet", kind)

		r := pingconfig.NewRegistry()
		r.Add(pingProfileOf(group))
		pingconfig.SetActive(r)
		body, err = json.Marshal(group)
		require.NoError(t, err, kind)
		var m map[string]any
		require.NoError(t, json.Unmarshal(body, &m), kind)
		assert.Equal(t, map[string]any{"destination": testUrl, "interval": 15.0, "sampling": 1.0, "timeout": 5000.0, "httpMethod": "GET"}, m["pingConfig"], kind)
		if kind != "select" {
			assert.Equal(t, testUrl, m["testUrl"], kind)
		}
		if c, ok := group.(interface{ Close() error }); ok {
			_ = c.Close()
		}
	}
}
