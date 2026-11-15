package common

import (
	"testing"

	"github.com/metacubex/quic-go"
	"github.com/stretchr/testify/assert"
)

func TestQUICParrot(t *testing.T) {
	assert.Equal(t, quic.ParrotNone, QUICParrot(true, "firefox"))
	assert.Equal(t, quic.ParrotNone, QUICParrot(true, ""))
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
		"safari":            quic.ParrotChrome, // no QUIC profile of its own here
		"ios":               quic.ParrotChrome,
		"android":           quic.ParrotChrome,
		"random":            quic.ParrotChrome, // whatever it picks for TLS
		"randomized":        quic.ParrotChrome,
		"none":              quic.ParrotChrome,
	} {
		assert.Equal(t, want, QUICParrot(false, fingerprint), fingerprint)
	}
}
