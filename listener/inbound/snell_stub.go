//go:build no_snell

package inbound

import (
	"errors"

	C "github.com/metacubex/mihomo/constant"
)

type SnellOption struct {
	BaseOption
	UDP bool `inbound:"udp,omitempty"`
}

func (o SnellOption) Equal(config C.InboundConfig) bool {
	return optionToString(o) == optionToString(config)
}

type Snell struct {
	*Base
}

func NewSnell(*SnellOption) (*Snell, error) {
	return nil, errors.New("Snell inbound is disabled by \"no_snell\" build tag")
}
