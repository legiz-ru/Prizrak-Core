package smart

import (
	"context"
	"crypto/x509"
	"errors"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	C "github.com/metacubex/mihomo/constant"

	"github.com/metacubex/http"
)

const (
	probeDefaultBlockTTL   = 10 * time.Minute
	probeTransientBlockTTL = 5 * time.Minute
	probeRegionalBlockTTL  = 30 * time.Minute
	probeMinBlockTTL       = 60 * time.Second

	responseProbeDownloadThresholdMB = 0.03

	ProbeTimeout                 = 8 * time.Second
	probeMinIntervalPerNode      = 120 * time.Second
	probeMinIntervalAfterFailure = 30 * time.Second
	probeRecentFailureWindow     = 10 * time.Minute
	probePerTargetPerMinute      = 6

	probeGlobalPerMinute = 120
	probeGlobalBurst     = 10
	probeMaxInflight     = 4

	probeHostBlindThreshold = 6
	probeHostBlindWindow    = 30 * time.Minute

	probeMaxEntries = 4096
	probePath       = "/robots.txt"
)

var (
	globalProbeThrottle struct {
		mu         sync.Mutex
		tokens     float64
		lastRefill time.Time
	}

	probeInflight = make(chan struct{}, probeMaxInflight)
)

type VerdictAction uint8

const (
	VerdictIgnore VerdictAction = iota
	VerdictReachable
	VerdictRecord
)

type (
	Verdict struct {
		Action VerdictAction
		TTL    time.Duration
		Reason string
	}

	ProbeResult struct {
		StatusCode int
		Header     http.Header
	}

	StatusProber interface {
		StatusProbe(ctx context.Context, rawURL string) (*ProbeResult, error)
	}

	probeNodeState struct {
		lastProbe   time.Time
		lastFailure time.Time
	}

	probeWindow struct {
		start time.Time
		count int
	}

	probeHostState struct {
		windowStart time.Time
		answers     int
		refusals    int
		blindUntil  time.Time
	}

	ProbeThrottle struct {
		mu      sync.Mutex
		nodes   map[string]*probeNodeState
		targets map[string]*probeWindow
		hosts   map[string]*probeHostState
	}
)

// ClassifyResponse turns the answer of a node into a verdict: only what identifies the node
// itself may record a block, a redirect that leaves the host must neither record nor clear.
func ClassifyResponse(status int, header http.Header, now time.Time) Verdict {
	switch {
	case isChallenge(header):
		return record(probeDefaultBlockTTL, "challenge")
	case status == http.StatusTooManyRequests:
		return record(rateLimitTTL(header, now), "rate limited")
	case status == http.StatusForbidden && isRateLimited(header, now):
		return record(rateLimitTTL(header, now), "rate limited")
	case status == http.StatusOK && strings.TrimSpace(header.Get("X-Ratelimit-Remaining")) == "0":
		return record(rateLimitTTL(header, now), "quota exhausted")
	case status == http.StatusForbidden:
		return record(probeDefaultBlockTTL, "forbidden")
	case status == http.StatusUnavailableForLegalReasons:
		return record(probeRegionalBlockTTL, "unavailable for legal reasons")
	case status == http.StatusMisdirectedRequest:
		return ignore("misdirected request")
	case status >= 300 && status < 400:
		return ignore("redirect")
	case status == http.StatusMethodNotAllowed || status == http.StatusNotImplemented:
		return ignore("method not allowed")
	case status >= 500:
		if _, ok := parseRetryAfter(header.Get("Retry-After"), now); ok {
			return record(rateLimitTTL(header, now), "overloaded")
		}
		return record(probeTransientBlockTTL, "origin error")
	case status >= 200:
		return reachable("answered")
	default:
		return ignore("unknown status")
	}
}

func ClassifyProbeError(err error) Verdict {
	if err == nil {
		return ignore("no probe")
	}
	var hostnameErr x509.HostnameError
	if errors.As(err, &hostnameErr) {
		return record(probeDefaultBlockTTL, "certificate hostname mismatch")
	}
	var authorityErr x509.UnknownAuthorityError
	if errors.As(err, &authorityErr) {
		return record(probeDefaultBlockTTL, "unknown certificate authority")
	}
	if isTimeout(err) {
		return record(probeTransientBlockTTL, "probe timed out")
	}
	return ignore("probe failed")
}

// A cancelled probe is not a timeout, it comes from the group shutting down instead of the node.
func isTimeout(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func parseRetryAfter(value string, now time.Time) (time.Duration, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, false
	}
	if seconds, err := strconv.ParseInt(value, 10, 64); err == nil {
		if seconds <= 0 {
			return 0, false
		}
		return time.Duration(seconds) * time.Second, true
	}
	if t, err := http.ParseTime(value); err == nil && t.After(now) {
		return t.Sub(now), true
	}
	return 0, false
}

func rateLimitTTL(header http.Header, now time.Time) time.Duration {
	if d, ok := parseRetryAfter(header.Get("Retry-After"), now); ok {
		return d
	}
	if epoch, err := strconv.ParseInt(strings.TrimSpace(header.Get("X-Ratelimit-Reset")), 10, 64); err == nil && epoch > now.Unix() {
		return time.Duration(epoch-now.Unix()) * time.Second
	}
	return probeDefaultBlockTTL
}

func isChallenge(header http.Header) bool {
	if strings.EqualFold(strings.TrimSpace(header.Get("Cf-Mitigated")), "challenge") {
		return true
	}
	switch strings.ToLower(strings.TrimSpace(header.Get("X-Amzn-Waf-Action"))) {
	case "challenge", "captcha":
		return true
	}
	return false
}

func isRateLimited(header http.Header, now time.Time) bool {
	if strings.TrimSpace(header.Get("X-Ratelimit-Remaining")) == "0" {
		return true
	}
	_, ok := parseRetryAfter(header.Get("Retry-After"), now)
	return ok
}

func ignore(reason string) Verdict {
	return Verdict{Action: VerdictIgnore, Reason: reason}
}

func reachable(reason string) Verdict {
	return Verdict{Action: VerdictReachable, Reason: reason}
}

func record(ttl time.Duration, reason string) Verdict {
	if ttl < probeMinBlockTTL {
		ttl = probeMinBlockTTL
	}
	if ttl > probeMaxBlockTTL {
		ttl = probeMaxBlockTTL
	}
	return Verdict{Action: VerdictRecord, TTL: ttl, Reason: reason}
}

func (t *ProbeThrottle) ensureMaps() {
	if t.nodes == nil {
		t.nodes = make(map[string]*probeNodeState)
		t.targets = make(map[string]*probeWindow)
		t.hosts = make(map[string]*probeHostState)
	}
}

func (t *ProbeThrottle) AllowNode(target, node string, now time.Time) bool {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.ensureMaps()
	t.trim(now)

	key := probeKey(target, node)
	state := t.nodes[key]
	if state != nil {
		interval := probeMinIntervalPerNode
		if !state.lastFailure.IsZero() && now.Sub(state.lastFailure) < probeRecentFailureWindow {
			interval = probeMinIntervalAfterFailure
		}
		if now.Sub(state.lastProbe) < interval {
			return false
		}
	}

	window := t.targets[target]
	if window == nil || now.Sub(window.start) >= time.Minute {
		window = &probeWindow{start: now}
		t.targets[target] = window
	}
	if window.count >= probePerTargetPerMinute {
		return false
	}

	if state == nil {
		state = &probeNodeState{}
		t.nodes[key] = state
	}
	state.lastProbe = now
	window.count++
	return true
}

// A host that refuses every node without ever answering says nothing about a single node, so its
// records are dropped while it stays blind; this keeps probe hostile hosts from draining the pool.
func (t *ProbeThrottle) AllowHostRecord(host string, verdict Verdict, now time.Time) bool {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.ensureMaps()
	state := t.hosts[host]
	if state == nil {
		state = &probeHostState{windowStart: now}
		t.hosts[host] = state
	}
	if now.Sub(state.windowStart) >= probeHostBlindWindow {
		state.windowStart = now
		state.answers = 0
		state.refusals = 0
	}

	if verdict.Action == VerdictReachable {
		state.answers++
		state.refusals = 0
		state.blindUntil = time.Time{}
		return true
	}
	if now.Before(state.blindUntil) {
		return false
	}
	if state.answers > 0 {
		return true
	}
	state.refusals++
	if state.refusals >= probeHostBlindThreshold {
		state.blindUntil = now.Add(probeHostBlindWindow)
		return false
	}
	return true
}

func (t *ProbeThrottle) NoteFailure(target, node string, now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.ensureMaps()

	key := probeKey(target, node)
	state := t.nodes[key]
	if state == nil {
		state = &probeNodeState{lastProbe: now}
		t.nodes[key] = state
	}
	state.lastFailure = now
}

func (t *ProbeThrottle) trim(now time.Time) {
	if len(t.nodes) > probeMaxEntries {
		for key, state := range t.nodes {
			if now.Sub(state.lastProbe) > probeRecentFailureWindow && now.Sub(state.lastFailure) > probeRecentFailureWindow {
				delete(t.nodes, key)
			}
		}
	}
	if len(t.targets) > probeMaxEntries {
		for target, window := range t.targets {
			if now.Sub(window.start) >= time.Minute {
				delete(t.targets, target)
			}
		}
	}
	if len(t.hosts) > probeMaxEntries {
		for host, state := range t.hosts {
			if now.Sub(state.windowStart) >= probeHostBlindWindow {
				delete(t.hosts, host)
			}
		}
	}
}

func probeKey(target, node string) string {
	return target + "\x00" + node
}

func AllowGlobalProbe(now time.Time) bool {
	globalProbeThrottle.mu.Lock()
	defer globalProbeThrottle.mu.Unlock()

	if globalProbeThrottle.lastRefill.IsZero() {
		globalProbeThrottle.tokens = probeGlobalBurst
		globalProbeThrottle.lastRefill = now
	}
	if elapsed := now.Sub(globalProbeThrottle.lastRefill); elapsed > 0 {
		globalProbeThrottle.tokens += elapsed.Minutes() * probeGlobalPerMinute
		if globalProbeThrottle.tokens > probeGlobalBurst {
			globalProbeThrottle.tokens = probeGlobalBurst
		}
		globalProbeThrottle.lastRefill = now
	}
	if globalProbeThrottle.tokens < 1 {
		return false
	}
	globalProbeThrottle.tokens--
	return true
}

func TryStartProbe() (func(), bool) {
	select {
	case probeInflight <- struct{}{}:
		return func() { <-probeInflight }, true
	default:
		return nil, false
	}
}

// A connection that downloaded almost nothing may have been answered with an error or limit page.
func ResponseProbeEligible(metadata *C.Metadata, downloadTotalMB float64, isUDP bool) bool {
	return !isUDP &&
		metadata.Host != "" &&
		metadata.Type != C.INNER &&
		metadata.DstPort == 443 &&
		downloadTotalMB < responseProbeDownloadThresholdMB
}

// API and CDN subdomains answer the root path with a 403 that says nothing about the node.
func ProbeURL(host string) string {
	return "https://" + host + probePath
}
