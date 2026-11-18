//go:build no_shadowquic

package inbound

import (
	"errors"

	C "github.com/metacubex/mihomo/constant"
)

type ShadowQuicOption struct {
	BaseOption
	ALPN                 []string `inbound:"alpn,omitempty"`
	ZeroRTT              bool     `inbound:"zero-rtt,omitempty"`
	CongestionController string   `inbound:"congestion-controller,omitempty"`
	MaxIdleTime          int      `inbound:"max-idle-time,omitempty"`
	MaxDatagramFrameSize int      `inbound:"max-datagram-frame-size,omitempty"`
}

func (o ShadowQuicOption) Equal(config C.InboundConfig) bool {
	return optionToString(o) == optionToString(config)
}

type ShadowQuic struct {
	*Base
}

func NewShadowQuic(*ShadowQuicOption) (*ShadowQuic, error) {
	return nil, errors.New("ShadowQUIC inbound is disabled by \"no_shadowquic\" build tag")
}
