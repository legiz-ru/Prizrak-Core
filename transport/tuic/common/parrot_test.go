package common

import (
	"testing"

	"github.com/metacubex/quic-go"
	"github.com/stretchr/testify/assert"
)

func TestQUICParrot(t *testing.T) {
	assert.Equal(t, quic.ParrotNone, QUICParrot(true, "firefox", false))
	assert.Equal(t, quic.ParrotNone, QUICParrot(true, "safari", false))
	assert.Equal(t, quic.ParrotNone, QUICParrot(true, "", false))
	for fingerprint, want := range map[string]quic.Parrot{
		"":                  quic.ParrotChrome,
		"chrome":            quic.ParrotChrome,
		"firefox":           quic.ParrotFirefox,
		"Firefox":           quic.ParrotFirefox,
		"HelloFirefox_Auto": quic.ParrotFirefox,
		"hellofirefox_156":  quic.ParrotFirefox,
		"hellofirefox_160":  quic.ParrotFirefox,
		"firefox120":        quic.ParrotChrome, // an explicit older hello keeps Chrome's
		"hellofirefox_120":  quic.ParrotChrome,
		"edge":              quic.ParrotChrome,
		"safari":            quic.ParrotSafari,
		"Safari":            quic.ParrotSafari,
		"hellosafari_auto":  quic.ParrotSafari,
		"hellosafari_27_2":  quic.ParrotSafari,
		"safari16":          quic.ParrotChrome,
		"hellosafari_26_3":  quic.ParrotChrome,
		"ios":               quic.ParrotChrome, // as Xray: no QUIC profile of its own
		"android":           quic.ParrotChrome,
		"random":            quic.ParrotChrome, // whatever it picks for TLS
		"randomized":        quic.ParrotChrome,
		"none":              quic.ParrotChrome,
	} {
		assert.Equal(t, want, QUICParrot(false, fingerprint, false), fingerprint)
	}
	// The captured Safari hello has no ECH: with ECH, Chrome's.
	assert.Equal(t, quic.ParrotChrome, QUICParrot(false, "safari", true))
	assert.Equal(t, quic.ParrotFirefox, QUICParrot(false, "firefox", true))
	assert.Equal(t, quic.ParrotChrome, QUICParrot(false, "chrome", true))
}
