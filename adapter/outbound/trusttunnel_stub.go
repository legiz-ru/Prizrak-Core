//go:build no_trusttunnel

package outbound

import "errors"

type TrustTunnel struct {
	*Base
}

type TrustTunnelOption struct {
	BasicOption
	Name string `proxy:"name"`
}

func NewTrustTunnel(TrustTunnelOption) (*TrustTunnel, error) {
	return nil, errors.New("TrustTunnel support is disabled by \"no_trusttunnel\" build tag")
}
