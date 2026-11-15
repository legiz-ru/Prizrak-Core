package convert_test

import (
	"net/url"
	"strings"
	"testing"

	"github.com/metacubex/mihomo/adapter"
	. "github.com/metacubex/mihomo/common/convert"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Xray's XHTTP/3 and XDRIVE-over-h3 clients parrot a browser's QUIC handshake
// unless finalmask.quicParams.disableChromeParrot, the browser of
// tlsSettings.fingerprint. The core does by default: only
// disableChromeParrot: true is mapped, to disable-chrome-parrot; over h2
// nothing changes.
func TestConvertsXrayJSONHTTP3DisableChromeParrot(t *testing.T) {
	xhttp := func(remarks, alpn, fp, finalmask string) string {
		s := `{"remarks":"` + remarks + `","outbounds":[{"tag":"proxy","protocol":"vless","settings":{"address":"a.example.com","port":443,"id":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"},
  "streamSettings":{"network":"xhttp","xhttpSettings":{"path":"/x"},"security":"tls","tlsSettings":{"serverName":"a.example.com","alpn":["` + alpn + `"]` + fp + `}`
		if finalmask != "" {
			s += `,"finalmask":` + finalmask
		}
		return s + `}}]}`
	}
	sub := "[" + strings.Join([]string{
		xhttp("default", "h3", `,"fingerprint":"firefox"`, ""),
		xhttp("enabled", "h3", "", `{"quicParams":{"disableChromeParrot":false}}`),
		xhttp("disabled", "h3", `,"fingerprint":"firefox"`, `{"quicParams":{"disableChromeParrot":true}}`),
		xhttp("h2", "h2", `,"fingerprint":"firefox"`, `{"quicParams":{"disableChromeParrot":true}}`),
	}, ",") + "]"
	proxies, err := ConvertsXrayJSON([]byte(sub))
	require.NoError(t, err)
	require.Len(t, proxies, 4)
	byName := map[string]map[string]any{}
	for _, p := range proxies {
		byName[p["name"].(string)] = p
		_, err := adapter.ParseProxy(p)
		require.NoError(t, err, p["name"])
	}
	assert.NotContains(t, byName["default"], "disable-chrome-parrot")
	assert.Equal(t, "firefox", byName["default"]["client-fingerprint"])
	assert.NotContains(t, byName["enabled"], "disable-chrome-parrot")
	assert.Equal(t, "chrome", byName["enabled"]["client-fingerprint"])
	assert.Equal(t, true, byName["disabled"]["disable-chrome-parrot"])
	assert.NotContains(t, byName["h2"], "disable-chrome-parrot")

	xdrive := strings.Replace(xdriveXrayJSON, `"alpn":["h2"]`, `"alpn":["h3"]`, 1)
	proxies, err = ConvertsXrayJSON([]byte(xdrive))
	require.NoError(t, err)
	assert.NotContains(t, proxies[0], "disable-chrome-parrot")
	disabled := strings.Replace(xdrive, `"network":"xdrive"`, `"finalmask":{"quicParams":{"disableChromeParrot":true}},"network":"xdrive"`, 1)
	require.NotEqual(t, xdrive, disabled)
	proxies, err = ConvertsXrayJSON([]byte(disabled))
	require.NoError(t, err)
	assert.Equal(t, true, proxies[0]["disable-chrome-parrot"])
}

// A hysteria outbound keeps the default browser handshake, the browser of its
// fingerprint.
func TestConvertsXrayJSONHysteria2Fingerprint(t *testing.T) {
	sub := `{"remarks":"hy","outbounds":[{"tag":"proxy","protocol":"hysteria","settings":{"address":"a.example.com","port":443,"version":2},
  "streamSettings":{"network":"hysteria","hysteriaSettings":{"version":2,"auth":"pw"},"security":"tls","tlsSettings":{"serverName":"a.example.com","fingerprint":"firefox"}}}]}`
	proxies, err := ConvertsXrayJSON([]byte(sub))
	require.NoError(t, err)
	assert.NotContains(t, proxies[0], "disable-chrome-parrot")
	assert.Equal(t, "firefox", proxies[0]["client-fingerprint"])
	_, err = adapter.ParseProxy(proxies[0])
	require.NoError(t, err)
}

// A link's fm with quicParams.disableChromeParrot: true sets
// disable-chrome-parrot over h3; fp of a hysteria2 link is its
// client-fingerprint.
func TestConvertsV2RayHTTP3DisableChromeParrot(t *testing.T) {
	base := "vless://b831381d-6324-4d53-ad4f-8cda48b30811@a.example.com:443?type=xhttp&path=%2Fx&security=tls&sni=a.example.com&alpn=h3&fp=firefox"
	for _, tc := range []struct {
		fm   string
		want any
	}{
		{"", nil},
		{`{"quicParams":{"disableChromeParrot":false}}`, nil},
		{`{"quicParams":{"disableChromeParrot":true}}`, true},
	} {
		link := base
		if tc.fm != "" {
			link += "&fm=" + url.QueryEscape(tc.fm)
		}
		proxies, err := ConvertsV2Ray([]byte(link + "#x"))
		require.NoError(t, err)
		assert.Equal(t, tc.want, proxies[0]["disable-chrome-parrot"], tc.fm)
		assert.Equal(t, "firefox", proxies[0]["client-fingerprint"])
		_, err = adapter.ParseProxy(proxies[0])
		require.NoError(t, err)
	}
	// Over h2 the fm key does nothing.
	link := strings.Replace(base, "alpn=h3", "alpn=h2", 1) + "&fm=" + url.QueryEscape(`{"quicParams":{"disableChromeParrot":true}}`) + "#x"
	proxies, err := ConvertsV2Ray([]byte(link))
	require.NoError(t, err)
	assert.NotContains(t, proxies[0], "disable-chrome-parrot")

	proxies, err = ConvertsV2Ray([]byte("hysteria2://pw@a.example.com:443/?sni=a.example.com&fp=firefox#hy2"))
	require.NoError(t, err)
	assert.Equal(t, "firefox", proxies[0]["client-fingerprint"])
	_, err = adapter.ParseProxy(proxies[0])
	require.NoError(t, err)
}
