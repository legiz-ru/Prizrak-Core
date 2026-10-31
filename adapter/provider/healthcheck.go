package provider

import (
	"context"
	"math/rand"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/atomic"
	"github.com/metacubex/mihomo/common/singledo"
	"github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/component/pingconfig"
	"github.com/metacubex/mihomo/component/powersave"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"

	"github.com/dlclark/regexp2"
	"golang.org/x/sync/errgroup"
)

type HealthCheckOption struct {
	URL      string
	Interval uint
}

type extraOption struct {
	expectedStatus utils.IntRanges[uint16]
	filters        map[string]struct{}
}

type HealthCheck struct {
	ctx            context.Context
	ctxCancel      context.CancelFunc
	url            string
	extra          map[string]*extraOption
	mu             sync.Mutex
	proxies        []C.Proxy
	interval       time.Duration
	lazy           bool
	expectedStatus utils.IntRanges[uint16]
	lastTouch      atomic.TypedValue[time.Time]
	lastCheck      atomic.TypedValue[time.Time]
	singleDo       *singledo.Single[struct{}]
	scheduledDo    *singledo.Single[struct{}]
	timeout        time.Duration
}

// backgroundInterval is how often, at most, the scheduled checks run while the
// device is in powersave.Background (screen off): sing-box stops its url-test
// checks after the same 30 minutes without use. Checks after failed dials
// (outboundgroup's onDialFailed) are not scheduled ones and run whatever the
// mode, so a dead node is still left as before.
const backgroundInterval = 30 * time.Minute

func (hc *HealthCheck) process() {
	ticker := time.NewTicker(hc.interval)
	go hc.check()
	for url, profile := range hc.profiledURLs() {
		go hc.pingLoop(url, profile)
	}
	// missed: a scheduled check was held back by the power-save mode.
	missed := false
	for {
		changed := powersave.Changed()
		select {
		case <-ticker.C:
			if !hc.scheduledDue() {
				missed = true
				continue
			}
			missed = false
			hc.scheduledCheck()
		case <-changed:
			// Back in use after a check was held back, and the last one is
			// older than the interval: catch up once, as sing-box does after
			// a pause, rather than wait for the next tick.
			if missed && powersave.Current() == powersave.Active && time.Since(hc.lastCheck.Load()) >= hc.interval {
				missed = false
				hc.scheduledCheck()
			}
		case <-hc.ctx.Done():
			ticker.Stop()
			return
		}
	}
}

// scheduledDue says whether a tick's check may run in the current power-save
// mode: always when active, every backgroundInterval with the screen off
// (half a tick of slack, so a check landing a little early is not put off a
// whole interval), never while the device is idle.
func (hc *HealthCheck) scheduledDue() bool {
	switch powersave.Current() {
	case powersave.Background:
		return time.Since(hc.lastCheck.Load())+hc.interval/2 >= backgroundInterval
	case powersave.Idle:
		return false
	default:
		return true
	}
}

func (hc *HealthCheck) scheduledCheck() {
	lastTouch := hc.lastTouch.Load()
	since := time.Since(lastTouch)
	if !hc.lazy || since < hc.interval {
		if len(hc.profiledURLs()) == 0 {
			hc.check()
		} else {
			// the profiled urls are their loops' to check
			hc.run(hc.scheduledDo, false)
		}
	} else {
		log.Debugln("Skip once health check because we are lazy")
	}
}

func (hc *HealthCheck) setProxies(proxies []C.Proxy) {
	hc.proxies = proxies
}

func (hc *HealthCheck) registerHealthCheckTask(url string, expectedStatus utils.IntRanges[uint16], filter string, interval uint) {
	url = strings.TrimSpace(url)
	if len(url) == 0 || url == hc.url {
		log.Debugln("ignore invalid health check url: %s", url)
		return
	}

	hc.mu.Lock()
	defer hc.mu.Unlock()

	// if the provider has not set up health checks, then modify it to be the same as the group's interval
	if hc.interval == 0 {
		hc.interval = time.Duration(interval) * time.Second
	}

	if hc.extra == nil {
		hc.extra = make(map[string]*extraOption)
	}

	// prioritize the use of previously registered configurations, especially those from provider
	if _, ok := hc.extra[url]; ok {
		// provider default health check does not set filter
		if url != hc.url && len(filter) != 0 {
			splitAndAddFiltersToExtra(filter, hc.extra[url])
		}

		log.Debugln("health check url: %s exists", url)
		return
	}

	option := &extraOption{filters: map[string]struct{}{}, expectedStatus: expectedStatus}
	splitAndAddFiltersToExtra(filter, option)
	hc.extra[url] = option
}

func splitAndAddFiltersToExtra(filter string, option *extraOption) {
	filter = strings.TrimSpace(filter)
	if len(filter) != 0 {
		for _, regex := range strings.Split(filter, "`") {
			regex = strings.TrimSpace(regex)
			if len(regex) != 0 {
				option.filters[regex] = struct{}{}
			}
		}
	}
}

func (hc *HealthCheck) auto() bool {
	return hc.interval != 0
}

func (hc *HealthCheck) touch() {
	hc.lastTouch.Store(time.Now())
}

// check checks every url now: at start, after a provider update, on
// demand. A url with a ping-config profile is checked by it.
func (hc *HealthCheck) check() {
	hc.run(hc.singleDo, true)
}

// run checks the urls; without profiled, the ones a ping-config profile
// schedules itself are left to their own loop.
func (hc *HealthCheck) run(single *singledo.Single[struct{}], profiled bool) {
	if len(hc.proxies) == 0 {
		return
	}

	_, _, _ = single.Do(func() (struct{}, error) {
		id := utils.NewUUIDV4().String()
		log.Debugln("Start New Health Checking {%s}", id)
		b := new(errgroup.Group)
		b.SetLimit(10)

		// execute default health check
		option := &extraOption{filters: nil, expectedStatus: hc.expectedStatus}
		if profiled || pingconfig.Lookup(hc.url) == nil {
			hc.execute(b, hc.url, id, option)
		}

		// execute extra health check
		if len(hc.extra) != 0 {
			for url, option := range hc.extra {
				if profiled || pingconfig.Lookup(url) == nil {
					hc.execute(b, url, id, option)
				}
			}
		}
		_ = b.Wait()
		hc.lastCheck.Store(time.Now())
		log.Debugln("Finish A Health Checking {%s}", id)
		return struct{}{}, nil
	})
}

func (hc *HealthCheck) execute(b *errgroup.Group, url, uid string, option *extraOption) {
	url = strings.TrimSpace(url)
	if len(url) == 0 {
		log.Debugln("Health Check has been skipped due to testUrl is empty, {%s}", uid)
		return
	}

	filterReg, expectedStatus := option.compile()
	timeout := hc.timeout
	if profile := pingconfig.Lookup(url); profile != nil {
		timeout = profile.CheckTimeout(hc.timeout)
	}

	for _, proxy := range hc.proxies {
		// skip proxies that do not require health check
		if filterReg != nil {
			if match, _ := filterReg.MatchString(proxy.Name()); !match {
				continue
			}
		}

		p := proxy
		b.Go(func() error {
			ctx, cancel := context.WithTimeout(hc.ctx, timeout)
			defer cancel()
			log.Debugln("Health Checking, proxy: %s, url: %s, id: {%s}", p.Name(), url, uid)
			_, _ = p.URLTest(ctx, url, expectedStatus)
			log.Debugln("Health Checked, proxy: %s, url: %s, alive: %t, delay: %d ms uid: {%s}", p.Name(), url, p.AliveForTestUrl(url), p.LastDelayForTestUrl(url), uid)
			return nil
		})
	}
}

func (hc *HealthCheck) close() {
	hc.ctxCancel()
	pingconfig.Release(hc)
}

// compile returns the option's filter as one regexp, nil without one.
func (option *extraOption) compile() (*regexp2.Regexp, utils.IntRanges[uint16]) {
	if option == nil {
		return nil, nil
	}
	var filterReg *regexp2.Regexp
	if len(option.filters) != 0 {
		filters := make([]string, 0, len(option.filters))
		for filter := range option.filters {
			filters = append(filters, filter)
		}

		filterReg = regexp2.MustCompile(strings.Join(filters, "|"), regexp2.None)
	}
	return filterReg, option.expectedStatus
}

// profiledURLs are this check's urls that have a ping-config profile.
func (hc *HealthCheck) profiledURLs() map[string]*pingconfig.Profile {
	hc.mu.Lock()
	defer hc.mu.Unlock()
	urls := map[string]*pingconfig.Profile{}
	if profile := pingconfig.Lookup(strings.TrimSpace(hc.url)); profile != nil {
		urls[profile.URL] = profile
	}
	for url := range hc.extra {
		if profile := pingconfig.Lookup(url); profile != nil {
			urls[url] = profile
		}
	}
	return urls
}

// option is the check option of url: its expected status and filters.
func (hc *HealthCheck) option(url string) *extraOption {
	hc.mu.Lock()
	defer hc.mu.Unlock()
	if option, ok := hc.extra[url]; ok {
		return option
	}
	return &extraOption{expectedStatus: hc.expectedStatus}
}

// maxPingChecks is how many checks of a profile loop run at once.
const maxPingChecks = 10

// pingLoop checks the nodes at url by its ping-config profile: a cycle of
// Interval × Sampling, each node checked Sampling times at random moments
// of it. The first round is check's, at start.
func (hc *HealthCheck) pingLoop(url string, profile *pingconfig.Profile) {
	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	cycle := profile.Cycle()
	sem := make(chan struct{}, maxPingChecks)
	own := map[C.Proxy]time.Time{}
	var lastCycle time.Time
	timer := time.NewTimer(cycle)
	defer timer.Stop()
	for {
		select {
		case <-timer.C:
		case <-hc.ctx.Done():
			return
		}
		start := time.Now()
		timer.Reset(cycle)
		if !hc.pingCycleDue(cycle, lastCycle) {
			continue
		}
		lastCycle = start
		hc.pingCycle(url, profile, rnd, sem, own, start)
	}
}

// pingCycleDue says whether a cycle runs: not while a lazy group is unused,
// as scheduledCheck, and at the pace of the power-save mode.
func (hc *HealthCheck) pingCycleDue(cycle time.Duration, lastCycle time.Time) bool {
	switch powersave.Current() {
	case powersave.Background:
		if time.Since(lastCycle)+cycle/2 < backgroundInterval {
			return false
		}
	case powersave.Idle:
		return false
	}
	if hc.lazy && time.Since(hc.lastTouch.Load()) >= cycle {
		log.Debugln("Skip a ping-config cycle because we are lazy")
		return false
	}
	return true
}

// pingCycle runs one cycle's slots. A node another provider or group
// already schedules at url is left to it; a node checked by someone else
// (a manual test, a failed dial) less than half an interval ago is skipped
// once. own holds, per node, when the loop's own last check of it ends.
func (hc *HealthCheck) pingCycle(url string, profile *pingconfig.Profile, rnd *rand.Rand, sem chan struct{}, own map[C.Proxy]time.Time, start time.Time) {
	option := hc.option(url)
	filterReg, expectedStatus := option.compile()

	var nodes []C.Proxy
	keep := map[any]struct{}{}
	for _, proxy := range hc.proxies {
		if filterReg != nil {
			if match, _ := filterReg.MatchString(proxy.Name()); !match {
				continue
			}
		}
		keep[proxy] = struct{}{}
		if pingconfig.Claim(hc, proxy, url) {
			nodes = append(nodes, proxy)
		}
	}
	pingconfig.Retain(hc, url, keep)
	for proxy := range own {
		if _, ok := keep[proxy]; !ok {
			delete(own, proxy)
		}
	}
	if len(nodes) == 0 {
		return
	}

	timeout := profile.CheckTimeout(hc.timeout)
	timer := time.NewTimer(0)
	defer timer.Stop()
	<-timer.C
	for _, slot := range pingconfig.Plan(len(nodes), profile, rnd) {
		timer.Reset(time.Until(start.Add(slot.Offset)))
		select {
		case <-timer.C:
		case <-hc.ctx.Done():
			return
		}
		proxy := nodes[slot.Node]
		if history := proxy.DelayHistoryForTestUrl(url); len(history) > 0 {
			last := history[len(history)-1].Time
			if last.After(own[proxy]) && time.Since(last) < profile.Interval/2 {
				continue
			}
		}
		// our own result lands within the check's timeout
		own[proxy] = time.Now().Add(timeout)
		select {
		case sem <- struct{}{}:
		case <-hc.ctx.Done():
			return
		}
		go func() {
			defer func() { <-sem }()
			ctx, cancel := context.WithTimeout(hc.ctx, timeout)
			defer cancel()
			_, _ = proxy.URLTest(ctx, url, expectedStatus)
			log.Debugln("Ping-config checked, proxy: %s, url: %s, alive: %t, delay: %d ms", proxy.Name(), url, proxy.AliveForTestUrl(url), proxy.LastDelayForTestUrl(url))
		}()
	}

	if traffic := profile.DailyTraffic(len(nodes)); traffic > 1<<30 && profile.WarnOnce() {
		log.Warnln("[ping-config] %s: the destination checks of %d nodes take about %.1f GB a day; raise interval or use a smaller destination", profile.Group, len(nodes), float64(traffic)/(1<<30))
	}
}

func NewHealthCheck(proxies []C.Proxy, url string, timeout uint, interval uint, lazy bool, expectedStatus utils.IntRanges[uint16]) *HealthCheck {
	if url == "" {
		expectedStatus = nil
		interval = 0
	}
	if timeout == 0 {
		timeout = 5000
	}
	ctx, cancel := context.WithCancel(context.Background())

	return &HealthCheck{
		ctx:            ctx,
		ctxCancel:      cancel,
		proxies:        proxies,
		url:            url,
		timeout:        time.Duration(timeout) * time.Millisecond,
		extra:          map[string]*extraOption{},
		interval:       time.Duration(interval) * time.Second,
		lazy:           lazy,
		expectedStatus: expectedStatus,
		singleDo:       singledo.NewSingle[struct{}](time.Second),
		scheduledDo:    singledo.NewSingle[struct{}](time.Second),
	}
}
