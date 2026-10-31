//go:build with_powersave

package provider

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/common/singledo"
	"github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/component/powersave"
	C "github.com/metacubex/mihomo/constant"
)

// countingProxy answers URLTest and counts the calls; nothing else of
// C.Proxy is used by a health check.
type countingProxy struct {
	C.Proxy
	tests atomic.Int32
}

func (p *countingProxy) Name() string { return "counting" }

func (p *countingProxy) URLTest(ctx context.Context, url string, expectedStatus utils.IntRanges[uint16]) (uint16, error) {
	p.tests.Add(1)
	return 1, nil
}

func (p *countingProxy) AliveForTestUrl(url string) bool { return true }

func (p *countingProxy) LastDelayForTestUrl(url string) uint16 { return 1 }

func TestHealthCheckFollowsPowerSave(t *testing.T) {
	defer powersave.Set(powersave.Active)

	proxy := &countingProxy{}
	hc := NewHealthCheck([]C.Proxy{proxy}, "http://example.invalid", 1000, 1, false, nil)
	hc.interval = 50 * time.Millisecond           // shorter than the option's seconds allow
	hc.singleDo = singledo.NewSingle[struct{}](0) // no result kept between checks
	go hc.process()
	defer hc.close()

	wait := func(d time.Duration) int32 {
		before := proxy.tests.Load()
		time.Sleep(d)
		return proxy.tests.Load() - before
	}

	if n := wait(300 * time.Millisecond); n < 3 {
		t.Fatalf("active: %d checks in 300ms at a 50ms interval", n)
	}

	powersave.Set(powersave.Idle)
	time.Sleep(60 * time.Millisecond) // a check already under way finishes
	if n := wait(300 * time.Millisecond); n != 0 {
		t.Fatalf("idle: %d checks, want none", n)
	}

	powersave.Set(powersave.Background)
	if n := wait(300 * time.Millisecond); n != 0 {
		t.Fatalf("background, last check just now: %d checks, want none", n)
	}

	// Back in use with ticks held back and the last check older than the
	// interval: one check at once, before the next tick.
	before := proxy.tests.Load()
	powersave.Set(powersave.Active)
	time.Sleep(20 * time.Millisecond)
	if n := proxy.tests.Load() - before; n != 1 {
		t.Fatalf("back in use: %d checks within 20ms, want the catch-up one", n)
	}
}
