package provider

import (
	"net/http"
	"net/http/httptest"
	"testing"

	C "github.com/metacubex/mihomo/constant"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A proxy-provider with fallback-urls reads the subscription, and its
// subscription-userinfo, from the first address that answers.
func TestParseProxyProviderFallbackURLs(t *testing.T) {
	C.SetHomeDir(t.TempDir())
	main := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("subscription-userinfo", "upload=1; download=1; total=1; expire=1")
		w.WriteHeader(502)
	}))
	defer main.Close()
	backup := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("subscription-userinfo", "upload=10; download=20; total=300; expire=0")
		_, _ = w.Write([]byte("proxies:\n  - {name: a, type: socks5, server: 127.0.0.1, port: 1080}\n"))
	}))
	defer backup.Close()

	p, err := ParseProxyProvider("sub", map[string]any{
		"type":          "http",
		"url":           main.URL + "/sub?token=x",
		"fallback-urls": []any{backup.URL + "/sub?token=x"},
		"path":          "./proxies/sub.yaml",
	}, nil)
	require.NoError(t, err)
	defer p.(*ProxySetProvider).Close()
	require.NoError(t, p.Initial())
	require.Len(t, p.Proxies(), 1)
	assert.Equal(t, "a", p.Proxies()[0].Name())
	assert.Equal(t, &SubscriptionInfo{Upload: 10, Download: 20, Total: 300}, p.(*ProxySetProvider).subscriptionInfo)
	body, err := p.(*ProxySetProvider).MarshalJSON()
	require.NoError(t, err)
	assert.Contains(t, string(body), `"lastUrl":"`+backup.URL+`/sub"`)
	assert.NotContains(t, string(body), "token")
}

func TestParseProxyProviderBadFallbackURL(t *testing.T) {
	C.SetHomeDir(t.TempDir())
	_, err := ParseProxyProvider("sub", map[string]any{
		"type":          "http",
		"url":           "https://example.com/sub",
		"fallback-urls": []any{"https://mirror.example/sub", "socks5://mirror.example/sub"},
	}, nil)
	assert.ErrorContains(t, err, "fallback-urls")
}

// Without fallback-urls the provider API shows no lastUrl.
func TestParseProxyProviderWithoutFallbackHasNoLastURL(t *testing.T) {
	C.SetHomeDir(t.TempDir())
	p, err := ParseProxyProvider("sub", map[string]any{"type": "http", "url": "https://example.com/sub"}, nil)
	require.NoError(t, err)
	defer p.(*ProxySetProvider).Close()
	body, err := p.(*ProxySetProvider).MarshalJSON()
	require.NoError(t, err)
	assert.NotContains(t, string(body), "lastUrl")
}
