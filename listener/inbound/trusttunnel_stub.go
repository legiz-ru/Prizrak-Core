//go:build no_trusttunnel

package inbound

import (
	"errors"

	C "github.com/metacubex/mihomo/constant"
)

type TrustTunnelOption struct {
	BaseOption
}

func (o TrustTunnelOption) Equal(config C.InboundConfig) bool {
	return optionToString(o) == optionToString(config)
}

type TrustTunnel struct {
	*Base
}

func NewTrustTunnel(*TrustTunnelOption) (*TrustTunnel, error) {
	return nil, errors.New("TrustTunnel inbound is disabled by \"no_trusttunnel\" build tag")
}
