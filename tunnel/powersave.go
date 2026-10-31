package tunnel

import (
	"time"

	"github.com/metacubex/mihomo/component/powersave"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/constant/features"
)

const (
	// idleSessionAge: a QUIC session nothing has used for this long is closed
	// while the device is not in use (powersave.Background or Idle).
	idleSessionAge = time.Minute

	// idleSweepInterval: how often the sessions are looked at meanwhile.
	idleSweepInterval = time.Minute
)

func init() {
	if features.WithPowerSave {
		go sweepIdleSessions()
	}
}

// sweepIdleSessions closes, while the device is not in use, the sessions of
// adapters implementing C.IdleCloser that have stood unused: their keep-alive
// (10 s for Hysteria2 and TUIC) would otherwise wake the radio for as long as
// the screen stays off. Nothing happens on a host that never leaves
// powersave.Active.
func sweepIdleSessions() {
	active := true
	for {
		changed := powersave.Changed()
		if powersave.Current() == powersave.Active {
			active = true
			<-changed
			continue
		}

		// Leaving active use: the DNS-over-QUIC/HTTP3 connections, made with a
		// keep-alive, start again without one (dns/powersave.go).
		if active {
			active = false
			resolver.ResetConnection()
		}

		closeIdleSessions()

		timer := time.NewTimer(idleSweepInterval)
		select {
		case <-changed:
			timer.Stop()
		case <-timer.C:
		}
	}
}

func closeIdleSessions() {
	// Keyed by the closer, which only the pointer adapters above implement:
	// any adapter type would not do as a map key.
	seen := map[C.IdleCloser]struct{}{}
	visit := func(p C.Proxy) {
		closer, ok := p.Adapter().(C.IdleCloser)
		if !ok {
			return
		}
		if _, ok := seen[closer]; ok {
			return
		}
		seen[closer] = struct{}{}
		closer.CloseIdle(idleSessionAge)
	}

	for _, p := range Proxies() {
		visit(p)
	}
	for _, pd := range Providers() {
		for _, p := range pd.Proxies() {
			visit(p)
		}
	}
}
