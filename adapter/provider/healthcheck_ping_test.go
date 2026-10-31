package provider

import (
	"context"
	"math/rand"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/component/pingconfig"
	C "github.com/metacubex/mihomo/constant"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	pingURL  = "https://ping.test/generate_204"
	plainURL = "https://plain.test/generate_204"
)

// pingProxy answers URLTest, counting the calls per url and keeping a
// history of them; nothing else of C.Proxy is used by a health check.
type pingProxy struct {
	C.Proxy
	name      string
	mu        sync.Mutex
	tests     map[string]int
	history   map[string][]C.DelayHistory
	deadlines []time.Duration
}

func newPingProxy(name string) *pingProxy {
	return &pingProxy{name: name, tests: map[string]int{}, history: map[string][]C.DelayHistory{}}
}

func (p *pingProxy) Name() string { return p.name }

func (p *pingProxy) URLTest(ctx context.Context, url string, expectedStatus utils.IntRanges[uint16]) (uint16, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.tests[url]++
	p.history[url] = append(p.history[url], C.DelayHistory{Time: time.Now(), Delay: 10})
	if deadline, ok := ctx.Deadline(); ok {
		p.deadlines = append(p.deadlines, time.Until(deadline))
	}
	return 10, nil
}

func (p *pingProxy) count(url string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.tests[url]
}

func (p *pingProxy) record(url string, at time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.history[url] = append(p.history[url], C.DelayHistory{Time: at, Delay: 10})
}

func (p *pingProxy) DelayHistoryForTestUrl(url string) []C.DelayHistory {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]C.DelayHistory(nil), p.history[url]...)
}

func (p *pingProxy) AliveForTestUrl(url string) bool { return true }

func (p *pingProxy) LastDelayForTestUrl(url string) uint16 { return 10 }

func pingProxies(n int) ([]C.Proxy, []*pingProxy) {
	var proxies []C.Proxy
	var fakes []*pingProxy
	for i := 0; i < n; i++ {
		p := newPingProxy(string(rune('a' + i)))
		proxies = append(proxies, p)
		fakes = append(fakes, p)
	}
	return proxies, fakes
}

// pingProfile is a profile with a test-sized interval, below what a config
// may set.
func pingProfile(url string, interval time.Duration, sampling int) *pingconfig.Profile {
	return &pingconfig.Profile{
		URL: url, Destination: url, Method: pingconfig.MethodGET,
		Interval: interval, Sampling: sampling, Timeout: time.Second, Group: "auto",
	}
}

func activate(t *testing.T, profiles ...*pingconfig.Profile) {
	r := pingconfig.NewRegistry()
	for _, p := range profiles {
		r.Add(p)
	}
	pingconfig.SetActive(r)
	t.Cleanup(func() { pingconfig.SetActive(nil) })
}

// runCycle runs one cycle of hc's loop at url and waits for its checks.
func runCycle(hc *HealthCheck, profile *pingconfig.Profile, own map[C.Proxy]time.Time) {
	sem := make(chan struct{}, maxPingChecks)
	hc.pingCycle(profile.URL, profile, rand.New(rand.NewSource(1)), sem, own, time.Now())
	for i := 0; i < maxPingChecks; i++ {
		sem <- struct{}{}
	}
}

// A cycle checks every node sampling times.
func TestPingCycleChecksEachNodeSamplingTimes(t *testing.T) {
	profile := pingProfile(pingURL, 40*time.Millisecond, 3)
	activate(t, profile)
	proxies, fakes := pingProxies(4)
	hc := NewHealthCheck(proxies, pingURL, 1000, 300, false, nil)
	defer hc.close()

	start := time.Now()
	runCycle(hc, profile, map[C.Proxy]time.Time{})
	assert.GreaterOrEqual(t, time.Since(start), 80*time.Millisecond, "the last samples come in the third interval")
	for _, p := range fakes {
		assert.Equal(t, 3, p.count(pingURL), p.name)
	}
}

// Two providers (or groups) with the same nodes at one url check each node
// once per slot, not once each.
func TestPingCycleChecksASharedNodeOnce(t *testing.T) {
	profile := pingProfile(pingURL, 20*time.Millisecond, 1)
	activate(t, profile)
	proxies, fakes := pingProxies(3)
	first := NewHealthCheck(proxies, pingURL, 1000, 300, false, nil)
	second := NewHealthCheck(proxies, pingURL, 1000, 300, false, nil)
	defer first.close()
	defer second.close()

	runCycle(first, profile, map[C.Proxy]time.Time{})
	runCycle(second, profile, map[C.Proxy]time.Time{})
	for _, p := range fakes {
		assert.Equal(t, 1, p.count(pingURL), p.name)
	}

	// the first lets go: the second takes the nodes on, once the first's
	// results are no longer fresh
	first.close()
	time.Sleep(profile.Interval)
	runCycle(second, profile, map[C.Proxy]time.Time{})
	for _, p := range fakes {
		assert.Equal(t, 2, p.count(pingURL), p.name)
	}
}

// A node checked by someone else less than half an interval ago is skipped
// once; one of the loop's own checks does not count as someone else's.
func TestPingCycleSkipsAFreshResult(t *testing.T) {
	profile := pingProfile(pingURL, 40*time.Millisecond, 1)
	activate(t, profile)
	proxies, fakes := pingProxies(2)
	hc := NewHealthCheck(proxies, pingURL, 1000, 300, false, nil)
	defer hc.close()
	own := map[C.Proxy]time.Time{}

	profile.Interval = 20 * time.Millisecond
	// stamped ahead, node 0's result is within half an interval when its
	// random slot comes, however late a busy machine runs it
	fakes[0].record(pingURL, time.Now().Add(time.Second))
	fakes[1].record(pingURL, time.Now().Add(-time.Hour))
	runCycle(hc, profile, own)
	assert.Equal(t, 0, fakes[0].count(pingURL), "checked a moment ago")
	assert.Equal(t, 1, fakes[1].count(pingURL))

	// the loop's own result right before does not stop its next sample
	profile.Sampling = 2
	runCycle(hc, profile, own)
	assert.Equal(t, 3, fakes[1].count(pingURL))
}

// The filter of the url's task applies to the loop as to a check.
func TestPingCycleFollowsTheFilter(t *testing.T) {
	profile := pingProfile(pingURL, 20*time.Millisecond, 1)
	activate(t, profile)
	proxies, fakes := pingProxies(3)
	hc := NewHealthCheck(proxies, plainURL, 1000, 300, false, nil)
	defer hc.close()
	hc.registerHealthCheckTask(pingURL, nil, "a|c", 300)

	runCycle(hc, profile, map[C.Proxy]time.Time{})
	assert.Equal(t, 1, fakes[0].count(pingURL))
	assert.Equal(t, 0, fakes[1].count(pingURL))
	assert.Equal(t, 1, fakes[2].count(pingURL))
}

// A lazy group's cycle waits for use.
func TestPingCycleIsLazy(t *testing.T) {
	proxies, _ := pingProxies(1)
	hc := NewHealthCheck(proxies, pingURL, 1000, 300, true, nil)
	defer hc.close()
	assert.False(t, hc.pingCycleDue(time.Second, time.Time{}), "never used")
	hc.touch()
	assert.True(t, hc.pingCycleDue(time.Second, time.Time{}))

	eager := NewHealthCheck(proxies, pingURL, 1000, 300, false, nil)
	defer eager.close()
	assert.True(t, eager.pingCycleDue(time.Second, time.Time{}))
}

// Scheduled ticks leave a profiled url to its loop; a check now (start,
// provider update, API, max-failed-times) takes every url, the profiled
// one with its longer timeout.
func TestScheduledChecksLeaveProfiledURLsToTheirLoop(t *testing.T) {
	profile := pingProfile(pingURL, 20*time.Millisecond, 1)
	activate(t, profile)
	proxies, fakes := pingProxies(2)
	hc := NewHealthCheck(proxies, plainURL, 1000, 300, false, nil)
	defer hc.close()
	hc.registerHealthCheckTask(pingURL, nil, "", 300)

	hc.run(hc.scheduledDo, false)
	for _, p := range fakes {
		assert.Equal(t, 1, p.count(plainURL), p.name)
		assert.Equal(t, 0, p.count(pingURL), p.name)
	}

	hc.check()
	for _, p := range fakes {
		assert.Equal(t, 2, p.count(plainURL), p.name)
		assert.Equal(t, 1, p.count(pingURL), p.name)
	}

	var long int
	for _, d := range fakes[0].deadlines {
		if d > 1500*time.Millisecond {
			long++
		}
	}
	assert.Equal(t, 1, long, "the profiled check has 1 s + the profile's 1 s")
}

// Without ping-config the checks run as before: every url on the tick.
func TestHealthCheckWithoutPingConfigIsUnchanged(t *testing.T) {
	pingconfig.SetActive(nil)
	proxies, fakes := pingProxies(2)
	hc := NewHealthCheck(proxies, plainURL, 1000, 300, false, nil)
	defer hc.close()
	hc.registerHealthCheckTask(pingURL, nil, "", 300)
	assert.Empty(t, hc.profiledURLs())

	hc.run(hc.scheduledDo, false)
	for _, p := range fakes {
		assert.Equal(t, 1, p.count(plainURL), p.name)
		assert.Equal(t, 1, p.count(pingURL), p.name)
		for _, d := range p.deadlines {
			assert.LessOrEqual(t, d, time.Second)
		}
	}
}

// process starts the loop of each profiled url: the checks at start, then
// a cycle each interval; close stops them and lets the nodes go.
func TestProcessRunsThePingLoop(t *testing.T) {
	profile := pingProfile(pingURL, 60*time.Millisecond, 1)
	activate(t, profile)
	proxies, fakes := pingProxies(2)
	hc := NewHealthCheck(proxies, pingURL, 1000, 3600, false, nil)
	go hc.process()

	time.Sleep(400 * time.Millisecond)
	for _, p := range fakes {
		n := p.count(pingURL)
		assert.GreaterOrEqual(t, n, 4, "%s: the start and ~5 cycles", p.name)
		assert.LessOrEqual(t, n, 8, p.name)
	}

	hc.close()
	time.Sleep(100 * time.Millisecond)
	stopped := fakes[0].count(pingURL)
	time.Sleep(200 * time.Millisecond)
	assert.Equal(t, stopped, fakes[0].count(pingURL), "no checks after close")
	other := NewHealthCheck(proxies, pingURL, 1000, 3600, false, nil)
	defer other.close()
	assert.True(t, pingconfig.Claim(other, proxies[0], pingURL), "close let the nodes go")
}

// A GET profile whose estimated traffic is over ~1 GB a day warns once.
func TestPingCycleWarnsOfTraffic(t *testing.T) {
	profile := pingProfile(pingURL, 20*time.Millisecond, 1)
	activate(t, profile)
	proxies, _ := pingProxies(2)
	hc := NewHealthCheck(proxies, pingURL, 1000, 300, false, nil)
	defer hc.close()

	profile.NoteBody(1)
	runCycle(hc, profile, map[C.Proxy]time.Time{})
	require.True(t, profile.WarnOnce(), "1 byte every 20 ms is no warning")

	small := pingProfile(pingURL, 20*time.Millisecond, 1)
	activate(t, small)
	small.NoteBody(512 << 10)
	runCycle(hc, small, map[C.Proxy]time.Time{})
	assert.False(t, small.WarnOnce(), "the cycle warned already")
}
