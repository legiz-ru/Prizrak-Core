//go:build no_shadowquic

package outbound

import "errors"

type ShadowQuic struct {
	*Base
}

type ShadowQuicOption struct {
	BasicOption
	Name string `proxy:"name"`
}

func NewShadowQuic(ShadowQuicOption) (*ShadowQuic, error) {
	return nil, errors.New("ShadowQUIC support is disabled by \"no_shadowquic\" build tag")
}
