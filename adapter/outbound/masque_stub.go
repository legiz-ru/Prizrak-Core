//go:build no_masque

package outbound

import "errors"

type Masque struct {
	*Base
}

type MasqueOption struct {
	BasicOption
	Name string `proxy:"name"`
}

func NewMasque(MasqueOption) (*Masque, error) {
	return nil, errors.New("MASQUE support is disabled by \"no_masque\" build tag")
}
