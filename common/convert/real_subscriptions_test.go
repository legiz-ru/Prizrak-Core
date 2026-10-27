package convert_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/metacubex/mihomo/adapter"
	. "github.com/metacubex/mihomo/common/convert"

	"gopkg.in/yaml.v3"
)

// TestRealSubscriptions runs every *.body file of CONVERT_SUBS_DIR (the
// bodies of real subscriptions fetched with the User-Agents of Happ, INCY,
// Streisand, Shadowrocket and Hiddify) through the converter the provider
// would pick and through adapter.ParseProxy, logging names and types only.
func TestRealSubscriptions(t *testing.T) {
	dir := os.Getenv("CONVERT_SUBS_DIR")
	if dir == "" {
		t.Skip("CONVERT_SUBS_DIR is not set")
	}
	files, err := filepath.Glob(filepath.Join(dir, "*.body"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no *.body files in %s", dir)
	}
	for _, file := range files {
		file := file
		t.Run(filepath.Base(file), func(t *testing.T) {
			buf, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			trimmed := strings.TrimSpace(string(buf))
			if strings.HasPrefix(trimmed, "proxies:") || strings.Contains(trimmed, "\nproxies:") {
				t.Skip("mihomo YAML, not converted")
			}
			var proxies []map[string]any
			if strings.HasPrefix(trimmed, "[") || strings.HasPrefix(trimmed, "{") {
				proxies, err = ConvertsXrayJSON(buf)
			} else {
				proxies, err = ConvertsV2Ray(buf)
			}
			if err != nil {
				t.Fatal(err)
			}
			for _, p := range proxies {
				if _, err := adapter.ParseProxy(p); err != nil {
					t.Errorf("%v: %s", p["name"], err)
				}
				extras := []string{}
				for _, key := range []string{"serverDescription", "finalmask", "obfs", "ports", "name-cert-verify", "ech-opts"} {
					if v, ok := p[key]; ok && v != "" {
						extras = append(extras, key)
					}
				}
				if ro, ok := p["reality-opts"].(map[string]any); ok {
					if _, ok := ro["mldsa65-verify"]; ok {
						extras = append(extras, "mldsa65-verify")
					}
				}
				t.Logf("%-40q type=%-9s network=%-5v extras=%v", p["name"], p["type"], p["network"], extras)
			}
			t.Logf("%d proxies", len(proxies))
		})
	}
}

// TestRealSubscriptionsAgainstYAML compares what the converters make of the
// JSON and base64 bodies with the mihomo YAML the same panel serves to an
// extended client (<prefix>_prizrak.body): the keys that differ are logged.
func TestRealSubscriptionsAgainstYAML(t *testing.T) {
	dir := os.Getenv("CONVERT_SUBS_DIR")
	if dir == "" {
		t.Skip("CONVERT_SUBS_DIR is not set")
	}
	yamls, _ := filepath.Glob(filepath.Join(dir, "*_prizrak.body"))
	for _, yamlFile := range yamls {
		prefix := strings.TrimSuffix(filepath.Base(yamlFile), "_prizrak.body")
		raw, err := os.ReadFile(yamlFile)
		if err != nil {
			t.Fatal(err)
		}
		var schema struct {
			Proxies []map[string]any `yaml:"proxies"`
		}
		if err := yaml.Unmarshal(raw, &schema); err != nil {
			t.Fatal(err)
		}
		expected := map[string]map[string]any{}
		for _, p := range schema.Proxies {
			expected[p["name"].(string)] = p
		}
		others, _ := filepath.Glob(filepath.Join(dir, prefix+"_*.body"))
		for _, file := range others {
			if file == yamlFile {
				continue
			}
			t.Run(filepath.Base(file), func(t *testing.T) {
				buf, _ := os.ReadFile(file)
				trimmed := strings.TrimSpace(string(buf))
				var proxies []map[string]any
				var err error
				if strings.HasPrefix(trimmed, "[") {
					proxies, err = ConvertsXrayJSON(buf)
				} else {
					proxies, err = ConvertsV2Ray(buf)
				}
				if err != nil {
					t.Fatal(err)
				}
				for _, got := range proxies {
					name := got["name"].(string)
					want, ok := expected[name]
					if !ok {
						t.Logf("%q: not in the YAML", name)
						continue
					}
					for key, wv := range want {
						gv, ok := got[key]
						if !ok {
							t.Logf("%q: YAML has %s=%v, converter has nothing", name, key, describe(wv))
							continue
						}
						if fmt.Sprint(gv) != fmt.Sprint(wv) {
							t.Logf("%q: %s: YAML %v, converter %v", name, key, describe(wv), describe(gv))
						}
					}
					for key, gv := range got {
						if _, ok := want[key]; !ok {
							t.Logf("%q: converter adds %s=%v", name, key, describe(gv))
						}
					}
				}
			})
		}
	}
}

// describe hides the secrets of a value in the log.
func describe(v any) string {
	s := fmt.Sprint(v)
	if len(s) > 24 && !strings.Contains(s, " ") {
		return s[:6] + "…"
	}
	return s
}
