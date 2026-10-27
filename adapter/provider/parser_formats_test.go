package provider

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The proxy-provider parser takes mihomo YAML, Xray JSON (an array of
// configs or one config) and share links, plain or base64.
func TestProxiesParserFormats(t *testing.T) {
	parser, err := NewProxiesParser("test", nil, "", "", "", "", overrideSchema{}, "")
	require.NoError(t, err)

	link := "vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443?encryption=none&type=tcp&security=none#link"
	xrayJSON := `[{"remarks":"json","outbounds":[{"tag":"proxy","protocol":"vless","settings":{"vnext":[{"address":"example.com","port":443,"users":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"}]}]},"streamSettings":{"network":"tcp","security":"none"}},{"tag":"direct","protocol":"freedom"}]}]`
	xrayConfig := `{"log":{},"outbounds":[{"tag":"single","protocol":"trojan","settings":{"servers":[{"address":"example.com","port":443,"password":"pw"}]},"streamSettings":{"network":"tcp","security":"tls","tlsSettings":{"serverName":"example.com"}}}]}`
	yamlConfig := "proxies:\n  - name: yaml\n    type: vless\n    server: example.com\n    port: 443\n    uuid: b831381d-6324-4d53-ad4f-8cda48b30811\n"

	for name, tc := range map[string]struct{ body, want string }{
		"yaml":        {yamlConfig, "yaml"},
		"plain-link":  {link, "link"},
		"base64-link": {base64.StdEncoding.EncodeToString([]byte(link + "\n")), "link"},
		"xray-json":   {xrayJSON, "json"},
		"xray-config": {"\n " + xrayConfig, "single"},
		"xray-base64": {base64.StdEncoding.EncodeToString([]byte(xrayJSON)), "json"},
	} {
		t.Run(name, func(t *testing.T) {
			proxies, err := parser([]byte(tc.body))
			require.NoError(t, err)
			require.Len(t, proxies, 1)
			assert.Equal(t, tc.want, proxies[0].Name())
		})
	}

	for name, body := range map[string]string{
		"empty":        "",
		"garbage":      "not a subscription",
		"json-no-outb": `{"log":{}}`,
		"json-broken":  `[{"remarks":`,
	} {
		t.Run("error/"+name, func(t *testing.T) {
			_, err := parser([]byte(body))
			assert.Error(t, err)
		})
	}
}
