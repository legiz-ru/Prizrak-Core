package dns

import (
	"github.com/metacubex/mihomo/component/powersave"

	"github.com/metacubex/quic-go"
)

// quietQUICConfig drops the keep-alive of a DNS-over-QUIC/HTTP3 connection
// made while the device is not in use (component/powersave): its ping every
// 20 seconds kept the connection, and the radio, up for as long as the screen
// stayed off, with nothing to resolve. Without it the connection closes after
// its idle timeout and the next query opens one again (0-RTT with the token
// store). The connections open on leaving active use are reset then
// (tunnel/powersave.go).
func quietQUICConfig(cfg *quic.Config) *quic.Config {
	if cfg == nil || cfg.KeepAlivePeriod == 0 || powersave.Current() == powersave.Active {
		return cfg
	}
	cfg = cfg.Clone()
	cfg.KeepAlivePeriod = 0
	return cfg
}
