package config_test

import (
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/pingconfig"
	. "github.com/metacubex/mihomo/config"
	C "github.com/metacubex/mihomo/constant"
	_ "github.com/metacubex/mihomo/hub/executor" // Parse links temporaryUpdateGeneral from it

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// One profile per url: the first group's checks the url for every group on
// it, a different block on the same url is ignored, another url has its own.
func TestParsePingProfiles(t *testing.T) {
	C.SetHomeDir(t.TempDir())
	cfg, err := Parse([]byte(`
proxies:
  - {name: a, type: socks5, server: 127.0.0.1, port: 1080}
  - {name: b, type: socks5, server: 127.0.0.1, port: 1081}
proxy-groups:
  - name: auto
    type: url-test
    proxies: [a, b]
    url: https://www.gstatic.com/generate_204
    interval: 300
    ping-config:
      destination: https://speed.cloudflare.com/__down?bytes=51200
      interval: 15s
      http-method: GET
  - name: backup
    type: fallback
    proxies: [a, b]
    url: https://www.gstatic.com/generate_204
    ping-config:
      http-method: HEAD
  - name: plain
    type: load-balance
    proxies: [a, b]
    url: https://www.gstatic.com/generate_204
  - name: other
    type: url-test
    proxies: [a, b]
    url: https://cp.cloudflare.com/generate_204
    timeout: 2000
    ping-config: {}
rules:
  - MATCH,auto
`))
	require.NoError(t, err)
	require.NotNil(t, cfg.PingProfiles)
	assert.Equal(t, 2, cfg.PingProfiles.Len())

	gstatic := cfg.PingProfiles.Lookup("https://www.gstatic.com/generate_204")
	require.NotNil(t, gstatic)
	assert.Equal(t, "auto", gstatic.Group, "the first group's profile stays")
	assert.Equal(t, pingconfig.MethodGET, gstatic.Method)
	assert.Equal(t, 15*time.Second, gstatic.Interval)

	cf := cfg.PingProfiles.Lookup("https://cp.cloudflare.com/generate_204")
	require.NotNil(t, cf)
	assert.Equal(t, "other", cf.Group)
	assert.Equal(t, 2*time.Second, cf.Timeout)
	assert.Equal(t, 300*time.Second, cf.Interval)
}

func TestParseWithoutPingConfig(t *testing.T) {
	C.SetHomeDir(t.TempDir())
	cfg, err := Parse([]byte(`
proxies:
  - {name: a, type: socks5, server: 127.0.0.1, port: 1080}
proxy-groups:
  - {name: auto, type: url-test, proxies: [a], url: https://www.gstatic.com/generate_204}
rules:
  - MATCH,auto
`))
	require.NoError(t, err)
	assert.Equal(t, 0, cfg.PingProfiles.Len())
}

func TestParseRejectsABadPingConfig(t *testing.T) {
	C.SetHomeDir(t.TempDir())
	_, err := Parse([]byte(`
proxies:
  - {name: a, type: socks5, server: 127.0.0.1, port: 1080}
proxy-groups:
  - name: auto
    type: url-test
    proxies: [a]
    ping-config:
      http-method: POST
rules:
  - MATCH,auto
`))
	assert.ErrorContains(t, err, "http-method")
}
