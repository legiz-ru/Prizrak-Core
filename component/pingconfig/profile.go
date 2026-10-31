// Package pingconfig holds the ping-config of proxy groups: how the nodes
// behind a group url are checked, in the spirit of Xray's
// burstObservatory.pingConfig.
//
// The delay of a node still comes from the group url, measured as before
// (HEAD, unified-delay). A profile adds a check of its destination after
// it: the node is alive only when that request answers in time, so a node
// that sends headers and then stalls on the body counts as dead. It also
// spreads the checks over a cycle at random moments and, with sampling,
// judges a node by a window of results instead of the last one.
//
// A profile belongs to the url it is keyed by: every check of that url,
// whichever group, provider or API call asks for it, runs by the profile.
// The url stays the key of the delay history, so the API and the apps
// see the same testUrl as without a profile.
package pingconfig

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/common/structure"
)

const (
	MethodHEAD = "HEAD"
	MethodGET  = "GET"

	// MinInterval is the shortest interval a config may set.
	MinInterval = 10 * time.Second
	// MaxSampling bounds sampling: the window keeps 2×sampling results.
	MaxSampling = 32
	// MaxBody is how much of a GET body a check reads.
	MaxBody = 4 << 20

	defaultInterval = 300 * time.Second
	defaultTimeout  = 5000 * time.Millisecond
)

// Profile is the ping-config of one group url.
type Profile struct {
	// URL is the group url the profile is keyed by; its delay is the one
	// a node reports.
	URL string
	// Destination is asked after URL; it defaults to URL.
	Destination string
	// Method is MethodHEAD or MethodGET, for Destination.
	Method string
	// Interval is the base interval: a cycle is Interval × Sampling.
	Interval time.Duration
	// Sampling is how many checks of each node a cycle makes.
	Sampling int
	// Timeout bounds the request to Destination.
	Timeout time.Duration
	// Connectivity, when set, is asked DIRECT after a failed check: with
	// no answer the device is offline and the failure is not recorded.
	Connectivity string
	// Group is the group that set the profile, for logs.
	Group string

	bodyBytes atomic.Int64
	warned    atomic.Bool
}

// Defaults are what a ping-config takes from its group.
type Defaults struct {
	Group    string
	URL      string // the resolved group url
	Interval int    // group interval, seconds; 0 if unset
	Timeout  int    // group timeout, milliseconds; 0 if unset
}

type rawProfile struct {
	Destination  string `ping:"destination,omitempty"`
	Interval     any    `ping:"interval,omitempty"`
	Sampling     int    `ping:"sampling,omitempty"`
	Timeout      any    `ping:"timeout,omitempty"`
	HTTPMethod   string `ping:"http-method,omitempty"`
	Connectivity string `ping:"connectivity,omitempty"`
}

// Parse reads a group's ping-config block. Fields left out come from the
// group: destination from its url, interval and timeout from its own.
// warn receives notes on values that were adjusted.
func Parse(raw map[string]any, d Defaults, warn func(format string, args ...any)) (*Profile, error) {
	var r rawProfile
	decoder := structure.NewDecoder(structure.Option{TagName: "ping", WeaklyTypedInput: true})
	if err := decoder.Decode(raw, &r); err != nil {
		return nil, fmt.Errorf("ping-config: %w", err)
	}
	if d.URL == "" {
		return nil, fmt.Errorf("ping-config: the group has no url")
	}

	p := &Profile{
		URL:          d.URL,
		Destination:  strings.TrimSpace(r.Destination),
		Method:       strings.ToUpper(strings.TrimSpace(r.HTTPMethod)),
		Sampling:     r.Sampling,
		Connectivity: strings.TrimSpace(r.Connectivity),
		Group:        d.Group,
	}
	if p.Destination == "" {
		p.Destination = d.URL
	}
	if err := checkURL("destination", p.Destination); err != nil {
		return nil, err
	}
	if p.Connectivity != "" {
		if err := checkURL("connectivity", p.Connectivity); err != nil {
			return nil, err
		}
	}
	switch p.Method {
	case "":
		p.Method = MethodHEAD
	case MethodHEAD, MethodGET:
	default:
		return nil, fmt.Errorf("ping-config: http-method %q is not HEAD or GET", r.HTTPMethod)
	}
	switch {
	case p.Sampling == 0:
		p.Sampling = 1
	case p.Sampling < 0 || p.Sampling > MaxSampling:
		return nil, fmt.Errorf("ping-config: sampling %d is not between 1 and %d", p.Sampling, MaxSampling)
	}

	var err error
	if p.Interval, err = parseDuration("interval", r.Interval, time.Second); err != nil {
		return nil, err
	}
	if p.Interval == 0 {
		p.Interval = time.Duration(d.Interval) * time.Second
	}
	if p.Interval == 0 {
		p.Interval = defaultInterval
	}
	if p.Interval < MinInterval {
		if warn != nil {
			warn("ping-config of %s: interval %s is below %s, using %s", d.Group, p.Interval, MinInterval, MinInterval)
		}
		p.Interval = MinInterval
	}

	if p.Timeout, err = parseDuration("timeout", r.Timeout, time.Millisecond); err != nil {
		return nil, err
	}
	if p.Timeout == 0 {
		p.Timeout = time.Duration(d.Timeout) * time.Millisecond
	}
	if p.Timeout == 0 {
		p.Timeout = defaultTimeout
	}
	return p, nil
}

func checkURL(field, raw string) error {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("ping-config: %s %q is not an http or https address", field, raw)
	}
	return nil
}

// parseDuration takes "15s", "1m", "500ms", or a bare number in unit.
func parseDuration(field string, v any, unit time.Duration) (time.Duration, error) {
	var n float64
	switch v := v.(type) {
	case nil:
		return 0, nil
	case int:
		n = float64(v)
	case int64:
		n = float64(v)
	case uint64:
		n = float64(v)
	case float64:
		n = v
	case string:
		s := strings.TrimSpace(v)
		if s == "" {
			return 0, nil
		}
		f, err := strconv.ParseFloat(s, 64)
		if err != nil {
			d, err := time.ParseDuration(s)
			if err != nil || d < 0 {
				return 0, fmt.Errorf("ping-config: %s %q is not a duration", field, s)
			}
			return d, nil
		}
		n = f
	default:
		return 0, fmt.Errorf("ping-config: %s %v is not a duration", field, v)
	}
	if n < 0 {
		return 0, fmt.Errorf("ping-config: %s %v is negative", field, v)
	}
	return time.Duration(n * float64(unit)), nil
}

// Cycle is how long one round of checks takes: Interval × Sampling.
func (p *Profile) Cycle() time.Duration {
	return p.Interval * time.Duration(p.Sampling)
}

// Window is how far back sampled results count: two cycles, as in Xray.
func (p *Profile) Window() time.Duration {
	return 2 * p.Cycle()
}

// AsksDestination says whether a check makes a request to Destination
// after the url's: not when it would repeat the url's own HEAD.
func (p *Profile) AsksDestination() bool {
	return p.Method != MethodHEAD || p.Destination != p.URL
}

// CheckTimeout is how long a whole check may take, given the time the
// url's own request has.
func (p *Profile) CheckTimeout(urlTimeout time.Duration) time.Duration {
	if !p.AsksDestination() {
		return urlTimeout
	}
	return urlTimeout + p.Timeout
}

// HistoryLimit is how many results of the url a node keeps: enough for
// the window.
func (p *Profile) HistoryLimit(base int) int {
	if n := 2*p.Sampling + 1; n > base {
		return n
	}
	return base
}

// Same says whether two profiles check the same way.
func (p *Profile) Same(o *Profile) bool {
	return p.URL == o.URL && p.Destination == o.Destination && p.Method == o.Method &&
		p.Interval == o.Interval && p.Sampling == o.Sampling && p.Timeout == o.Timeout &&
		p.Connectivity == o.Connectivity
}

// NoteBody records the size of a GET body a check read.
func (p *Profile) NoteBody(n int64) {
	for {
		old := p.bodyBytes.Load()
		if n <= old || p.bodyBytes.CompareAndSwap(old, n) {
			return
		}
	}
}

// DailyTraffic estimates the bytes a day the destination checks of nodes
// nodes take, from the largest body read so far.
func (p *Profile) DailyTraffic(nodes int) int64 {
	if p.Method != MethodGET || p.Interval <= 0 {
		return 0
	}
	perDay := int64(24 * time.Hour / p.Interval)
	return p.bodyBytes.Load() * int64(nodes) * perDay
}

// WarnOnce reports whether this is the first call: for a one-time log.
func (p *Profile) WarnOnce() bool {
	return p.warned.CompareAndSwap(false, true)
}

func (p *Profile) MarshalJSON() ([]byte, error) {
	m := map[string]any{
		"destination": p.Destination,
		"interval":    int64(p.Interval / time.Second),
		"sampling":    p.Sampling,
		"timeout":     int64(p.Timeout / time.Millisecond),
		"httpMethod":  p.Method,
	}
	if p.Connectivity != "" {
		m["connectivity"] = p.Connectivity
	}
	return json.Marshal(m)
}
