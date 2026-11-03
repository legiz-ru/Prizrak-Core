package outbound

import (
	"context"

	C "github.com/metacubex/mihomo/constant"
)

// udp-443 option values
const (
	Udp443Allow  = "allow"  // default, do nothing
	Udp443Reject = "reject" // send UDP port 443 traffic (e.g. QUIC) that would go through this proxy into REJECT
)

// Udp443 is a ProxyAdapter wrapper controlled by the `udp-443` option.
type Udp443 struct {
	ProxyAdapter
	mode string
}

// ListenPacketContext implements C.ProxyAdapter
func (u *Udp443) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (C.PacketConn, error) {
	if u.mode == Udp443Reject && metadata.NetWork == C.UDP && metadata.DstPort == 443 {
		return NewReject().ListenPacketContext(ctx, metadata)
	}
	return u.ProxyAdapter.ListenPacketContext(ctx, metadata)
}

func NewUdp443(adapter ProxyAdapter, mode string) *Udp443 {
	return &Udp443{
		ProxyAdapter: adapter,
		mode:         mode,
	}
}
