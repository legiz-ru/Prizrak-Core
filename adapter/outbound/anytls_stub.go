//go:build no_anytls

package outbound

import "errors"

type AnyTLS struct {
	*Base
}

type AnyTLSOption struct {
	BasicOption
	Name string `proxy:"name"`
}

func NewAnyTLS(AnyTLSOption) (*AnyTLS, error) {
	return nil, errors.New("AnyTLS support is disabled by \"no_anytls\" build tag")
}
