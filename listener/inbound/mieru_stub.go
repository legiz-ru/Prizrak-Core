//go:build no_mieru

package inbound

import (
	"errors"

	C "github.com/metacubex/mihomo/constant"
)

type MieruOption struct {
	BaseOption
}

func (o MieruOption) Equal(config C.InboundConfig) bool {
	return optionToString(o) == optionToString(config)
}

type Mieru struct {
	*Base
}

func NewMieru(*MieruOption) (*Mieru, error) {
	return nil, errors.New("Mieru inbound is disabled by \"no_mieru\" build tag")
}
