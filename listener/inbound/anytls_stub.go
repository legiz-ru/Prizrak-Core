//go:build no_anytls

package inbound

import (
	"errors"

	C "github.com/metacubex/mihomo/constant"
)

type AnyTLSOption struct {
	BaseOption
}

func (o AnyTLSOption) Equal(config C.InboundConfig) bool {
	return optionToString(o) == optionToString(config)
}

type AnyTLS struct {
	*Base
}

func NewAnyTLS(*AnyTLSOption) (*AnyTLS, error) {
	return nil, errors.New("AnyTLS inbound is disabled by \"no_anytls\" build tag")
}
