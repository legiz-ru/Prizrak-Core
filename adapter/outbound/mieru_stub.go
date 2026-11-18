//go:build no_mieru

package outbound

import "errors"

type Mieru struct {
	*Base
}

type MieruOption struct {
	BasicOption
	Name string `proxy:"name"`
}

func NewMieru(MieruOption) (*Mieru, error) {
	return nil, errors.New("Mieru support is disabled by \"no_mieru\" build tag")
}
