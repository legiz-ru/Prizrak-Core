//go:build no_snell

package outbound

import "errors"

type Snell struct {
	*Base
}

type SnellOption struct {
	BasicOption
	Name string `proxy:"name"`
}

func NewSnell(SnellOption) (*Snell, error) {
	return nil, errors.New("Snell support is disabled by \"no_snell\" build tag")
}
