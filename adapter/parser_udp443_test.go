package adapter

import (
	"context"
	"net/netip"
	"strings"
	"testing"

	C "github.com/metacubex/mihomo/constant"
)

// dialTestUDP opens a test packet conn through the proxy on the given dst port
// and returns the outbound chain it ends up on.
func dialTestUDP(t *testing.T, proxy C.Proxy, port uint16) (string, error) {
	t.Helper()
	metadata := &C.Metadata{
		NetWork: C.UDP,
		DstIP:   netip.MustParseAddr("127.0.0.1"),
		DstPort: port,
	}
	pc, err := proxy.ListenPacketContext(context.Background(), metadata)
	if err != nil {
		return "", err
	}
	defer func() { _ = pc.Close() }()
	return pc.Chains().String(), nil
}

// Default (allow): traffic passes through to the outbound untouched.
func TestParseProxyUdp443DefaultAllow(t *testing.T) {
	proxy, err := ParseProxy(map[string]any{"name": "d", "type": "direct"})
	if err != nil {
		t.Fatal(err)
	}
	chain, err := dialTestUDP(t, proxy, 443)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(chain, "REJECT") {
		t.Fatalf("udp-443 default \"allow\" must route through the outbound, chain: %s", chain)
	}
}

// udp-443: reject and its `quic` alias send UDP 443 into REJECT and leave
// other ports alone.
func TestParseProxyUdp443Reject(t *testing.T) {
	for _, mapping := range []map[string]any{
		{"name": "d", "type": "direct", "udp-443": "reject"},
		{"name": "d", "type": "direct", "quic": "reject"},
		// the `quic` alias agrees with udp-443
		{"name": "d", "type": "direct", "udp-443": "reject", "quic": "reject"},
		// the structure decoder replaces "_" with "-" in keys
		{"name": "d", "type": "direct", "udp_443": "reject"},
	} {
		proxy, err := ParseProxy(mapping)
		if err != nil {
			t.Fatal(err)
		}
		chain, err := dialTestUDP(t, proxy, 443)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(chain, "REJECT") {
			t.Fatalf("option %v: UDP 443 must go to REJECT, chain: %s", mapping, chain)
		}

		chain, err = dialTestUDP(t, proxy, 853)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(chain, "REJECT") {
			t.Fatalf("option %v: UDP not on port 443 must pass through, chain: %s", mapping, chain)
		}
	}
}

// quic: allow explicitly keeps the default behavior.
func TestParseProxyUdp443ExplicitAllow(t *testing.T) {
	for _, key := range []string{"udp-443", "quic"} {
		proxy, err := ParseProxy(map[string]any{"name": "d", "type": "direct", key: "allow"})
		if err != nil {
			t.Fatal(err)
		}
		chain, err := dialTestUDP(t, proxy, 443)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(chain, "REJECT") {
			t.Fatalf("%s: allow must route through the outbound, chain: %s", key, chain)
		}
	}
}

func TestParseProxyUdp443Invalid(t *testing.T) {
	for _, mapping := range []map[string]any{
		{"name": "d", "type": "direct", "udp-443": "drop"},
		{"name": "d", "type": "direct", "quic": "drop"},
		// conflicting alias values
		{"name": "d", "type": "direct", "udp-443": "reject", "quic": "allow"},
		{"name": "d", "type": "direct", "udp-443": "allow", "quic": "reject"},
	} {
		if _, err := ParseProxy(mapping); err == nil {
			t.Fatalf("invalid option must be rejected: %v", mapping)
		}
	}
}
