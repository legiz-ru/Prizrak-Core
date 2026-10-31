package provider

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/metacubex/mihomo/component/resource"
	C "github.com/metacubex/mihomo/constant"
	mihomoTunnel "github.com/metacubex/mihomo/tunnel"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func noBundle(string) resource.BundleFile { return nil }

func init() { SetTunnel(mihomoTunnel.Tunnel) }

// A rule-provider with fallback-urls reads its rules from the first
// address that answers.
func TestParseRuleProviderFallbackURLs(t *testing.T) {
	C.SetHomeDir(t.TempDir())
	main := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500) }))
	defer main.Close()
	backup := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("payload:\n  - '+.example.com'\n  - 'example.org'\n"))
	}))
	defer backup.Close()

	p, err := ParseRuleProvider("ru-sites", map[string]any{
		"type":          "http",
		"behavior":      "domain",
		"url":           main.URL + "/ru.yaml",
		"fallback-urls": []any{"", main.URL + "/ru.yaml", backup.URL + "/ru.yaml"},
		"path":          "./rule-sets/ru-sites.yaml",
	}, nil, noBundle)
	require.NoError(t, err)
	defer p.(*RuleSetProvider).Close()
	require.NoError(t, p.Initial())
	assert.Equal(t, 2, p.Count())
	body, err := p.(*RuleSetProvider).MarshalJSON()
	require.NoError(t, err)
	assert.Contains(t, string(body), `"lastUrl":"`+backup.URL+`/ru.yaml"`)
}

func TestParseRuleProviderBadFallbackURL(t *testing.T) {
	C.SetHomeDir(t.TempDir())
	for _, urls := range []any{[]any{"ftp://mirror.example/ru.mrs"}, []any{"mirror.example/ru.mrs"}, []any{map[string]any{"url": "https://mirror.example"}}} {
		_, err := ParseRuleProvider("ru-sites", map[string]any{
			"type":          "http",
			"behavior":      "domain",
			"format":        "mrs",
			"url":           "https://example.com/ru.mrs",
			"fallback-urls": urls,
		}, nil, noBundle)
		assert.Error(t, err, "%v", urls)
	}
}
