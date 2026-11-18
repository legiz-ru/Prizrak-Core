//go:build no_ssr

package outbound

import "errors"

type ShadowSocksR struct {
	*Base
}

type ShadowSocksROption struct {
	BasicOption
	Name string `proxy:"name"`
}

func NewShadowSocksR(ShadowSocksROption) (*ShadowSocksR, error) {
	return nil, errors.New("ShadowsocksR support is disabled by \"no_ssr\" build tag")
}
