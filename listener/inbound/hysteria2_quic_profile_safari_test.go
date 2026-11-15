package inbound_test

import (
	"fmt"
	"testing"

	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/listener/inbound"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The profile of a Safari capture (Safari 27.2 on macOS 26.7.2) for
// client-fingerprint safari; ios is Chrome's, as in Xray. With ECH it is
// Chrome's too, as the captured hello has no ECH: the ECH subtests of
// testInboundHysteria2TLS take that way.
func TestInboundHysteria2_SafariParrot(t *testing.T) {
	inboundOptions := inbound.Hysteria2Option{
		Certificate: tlsCertificate,
		PrivateKey:  tlsPrivateKey,
	}
	outboundOptions := outbound.Hysteria2Option{
		Fingerprint:       tlsFingerprint,
		ClientFingerprint: "safari",
	}
	testInboundHysteria2TLS(t, inboundOptions, outboundOptions)
}

// Safari advertises no max_datagram_frame_size: the listener assumes DATAGRAM
// support of such a client, as Hysteria's servers do, so UDP comes back. Its
// Initials are 1200 bytes with an empty source connection ID.
func TestInboundHysteria2_SafariParrotUDP(t *testing.T) {
	for _, serverMTU := range []int{0, 1400} {
		serverMTU := serverMTU
		t.Run(fmt.Sprintf("server-mtu=%d", serverMTU), func(t *testing.T) {
			t.Parallel()
			tunnel, proxy, fwd := newHysteria2UDPEchoPair(t, inbound.Hysteria2Option{UdpMTU: serverMTU},
				outbound.Hysteria2Option{ClientFingerprint: "safari"}, 1)
			udpEcho(t, proxy, hysteria2UDPSizes)
			tunnel.DoSequentialTest(t, proxy)

			_, _, initials := fwd.stats()
			require.NotEmpty(t, initials)
			assert.Equal(t, 8, initials[0].dcidLen)
			for _, h := range initials {
				assert.Zero(t, h.scidLen, "source connection ID")
				assert.Equal(t, 1200, h.size)
			}
		})
	}
}

func TestHysteria2SafariProfileInitial(t *testing.T) {
	for _, fingerprint := range []string{"safari", "Safari", "hellosafari_auto"} {
		for _, ip := range []string{"127.0.0.1", "::1"} {
			size, scid := captureHysteria2Initial(t, ip, outbound.Hysteria2Option{ClientFingerprint: fingerprint})
			assert.Equal(t, 1200, size, fingerprint, ip)
			assert.Zero(t, scid, fingerprint, ip)
		}
	}
	// ios is Chrome's, as in Xray.
	size, scid := captureHysteria2Initial(t, "127.0.0.1", outbound.Hysteria2Option{ClientFingerprint: "ios"})
	assert.Equal(t, 1250, size)
	assert.Zero(t, scid)
	// With ECH, Chrome's.
	size, scid = captureHysteria2Initial(t, "127.0.0.1", outbound.Hysteria2Option{
		ClientFingerprint: "safari",
		ECHOpts:           outbound.ECHOptions{Enable: true, Config: echConfigBase64},
	})
	assert.Equal(t, 1250, size)
	assert.Zero(t, scid)
}
