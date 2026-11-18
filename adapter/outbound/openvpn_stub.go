//go:build no_openvpn

package outbound

import "errors"

type OpenVPN struct {
	*Base
}

type OpenVPNOption struct {
	BasicOption
	Name string `proxy:"name"`
}

func NewOpenVPN(OpenVPNOption) (*OpenVPN, error) {
	return nil, errors.New("OpenVPN support is disabled by \"no_openvpn\" build tag")
}
