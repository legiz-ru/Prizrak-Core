package common

import (
	"strings"

	"github.com/metacubex/quic-go"
)

// QUICParrot is the browser whose QUIC handshake a client imitates, as
// prizrak-quic-go's Config.Parrot, picked as Xray-core's clients pick it
// (ferrum's quic_profile): none with disable-chrome-parrot, otherwise the
// browser of the proxy's client-fingerprint. Firefox's names are Firefox
// 160; every other value is Chrome, the profile Xray sends for any
// fingerprint: an empty one, "ios", "random" (whatever hello it picks for
// TLS) and older hellos such as "firefox120" among them.
func QUICParrot(disableChromeParrot bool, clientFingerprint string) quic.Parrot {
	if disableChromeParrot {
		return quic.ParrotNone
	}
	switch strings.ToLower(clientFingerprint) {
	case "firefox", "hellofirefox_auto", "hellofirefox_156", "hellofirefox_160":
		return quic.ParrotFirefox
	default:
		return quic.ParrotChrome
	}
}
