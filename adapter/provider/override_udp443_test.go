package provider

import (
	"testing"

	"github.com/metacubex/mihomo/common/structure"
)

// TestOverrideUdp443 checks that `udp-443` and its `quic` alias are part of
// the provider override whitelist and are put into the proxy mapping before
// parse, so adapter.ParseProxy applies them.
func TestOverrideUdp443(t *testing.T) {
	decoder := structure.NewDecoder(structure.Option{TagName: "provider", WeaklyTypedInput: true})
	var schema overrideSchema
	err := decoder.Decode(map[string]any{
		"udp-443": "reject",
		"quic":    "allow",
	}, &schema)
	if err != nil {
		t.Fatal(err)
	}

	mapping := map[string]any{"name": "p"}
	if err := schema.Apply(mapping); err != nil {
		t.Fatal(err)
	}
	if mapping["udp-443"] != "reject" {
		t.Fatalf("udp-443 override not applied: %#v", mapping["udp-443"])
	}
	if mapping["quic"] != "allow" {
		t.Fatalf("quic override not applied: %#v", mapping["quic"])
	}
}

// Unknown override keys stay ignored, so an unset alias doesn't fake a value.
func TestOverrideUdp443Unset(t *testing.T) {
	decoder := structure.NewDecoder(structure.Option{TagName: "provider", WeaklyTypedInput: true})
	var schema overrideSchema
	if err := decoder.Decode(map[string]any{
		"udp-443": "reject",
	}, &schema); err != nil {
		t.Fatal(err)
	}

	mapping := map[string]any{"name": "p"}
	if err := schema.Apply(mapping); err != nil {
		t.Fatal(err)
	}
	if _, exist := mapping["quic"]; exist {
		t.Fatalf("unset quic must not appear in mapping: %#v", mapping["quic"])
	}
}
