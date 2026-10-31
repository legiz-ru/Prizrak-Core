package pingconfig

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"sync/atomic"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const groupURL = "https://www.gstatic.com/generate_204"

func defaults() Defaults {
	return Defaults{Group: "auto", URL: groupURL, Interval: 120, Timeout: 4000}
}

// Every field left out comes from the group, or from the defaults when the
// group has none either.
func TestParseInheritsFromTheGroup(t *testing.T) {
	p, err := Parse(map[string]any{}, defaults(), nil)
	require.NoError(t, err)
	assert.Equal(t, groupURL, p.URL)
	assert.Equal(t, groupURL, p.Destination)
	assert.Equal(t, MethodHEAD, p.Method)
	assert.Equal(t, 1, p.Sampling)
	assert.Equal(t, 120*time.Second, p.Interval)
	assert.Equal(t, 4*time.Second, p.Timeout)
	assert.Equal(t, "", p.Connectivity)
	assert.Equal(t, "auto", p.Group)

	p, err = Parse(map[string]any{}, Defaults{Group: "auto", URL: groupURL}, nil)
	require.NoError(t, err)
	assert.Equal(t, 300*time.Second, p.Interval)
	assert.Equal(t, 5*time.Second, p.Timeout)
}

func TestParseTakesTheBlock(t *testing.T) {
	p, err := Parse(map[string]any{
		"destination":  "https://speed.cloudflare.com/__down?bytes=51200",
		"interval":     "15s",
		"sampling":     3,
		"timeout":      "3s",
		"http-method":  "get",
		"connectivity": "http://connectivitycheck.gstatic.com/generate_204",
	}, defaults(), nil)
	require.NoError(t, err)
	assert.Equal(t, "https://speed.cloudflare.com/__down?bytes=51200", p.Destination)
	assert.Equal(t, MethodGET, p.Method)
	assert.Equal(t, 3, p.Sampling)
	assert.Equal(t, 15*time.Second, p.Interval)
	assert.Equal(t, 3*time.Second, p.Timeout)
	assert.Equal(t, "http://connectivitycheck.gstatic.com/generate_204", p.Connectivity)
	assert.Equal(t, 45*time.Second, p.Cycle())
	assert.Equal(t, 90*time.Second, p.Window())
}

// interval counts seconds and timeout milliseconds when bare; both take Go
// durations as strings.
func TestParseDurations(t *testing.T) {
	cases := []struct {
		interval, timeout any
		wantI, wantT      time.Duration
	}{
		{15, 3000, 15 * time.Second, 3 * time.Second},
		{"20", "2500", 20 * time.Second, 2500 * time.Millisecond},
		{"1m", "500ms", time.Minute, 500 * time.Millisecond},
		{30.0, 1500.0, 30 * time.Second, 1500 * time.Millisecond},
		{uint64(60), int64(800), time.Minute, 800 * time.Millisecond},
		{"", "", 120 * time.Second, 4 * time.Second},
	}
	for _, c := range cases {
		p, err := Parse(map[string]any{"interval": c.interval, "timeout": c.timeout}, defaults(), nil)
		require.NoError(t, err, "%v %v", c.interval, c.timeout)
		assert.Equal(t, c.wantI, p.Interval, "%v", c.interval)
		assert.Equal(t, c.wantT, p.Timeout, "%v", c.timeout)
	}
}

func TestParseRaisesAShortInterval(t *testing.T) {
	var warned int
	p, err := Parse(map[string]any{"interval": "2s"}, defaults(), func(string, ...any) { warned++ })
	require.NoError(t, err)
	assert.Equal(t, MinInterval, p.Interval)
	assert.Equal(t, 1, warned)
}

func TestParseRejectsBadValues(t *testing.T) {
	for _, raw := range []map[string]any{
		{"destination": "ftp://example.com/file"},
		{"destination": "example.com/file"},
		{"destination": "https://"},
		{"connectivity": "udp://example.com"},
		{"http-method": "POST"},
		{"sampling": -1},
		{"sampling": MaxSampling + 1},
		{"interval": "soon"},
		{"interval": "-5s"},
		{"timeout": -1},
		{"timeout": []any{1}},
		{"sampling": "many"},
	} {
		_, err := Parse(raw, defaults(), nil)
		assert.Error(t, err, "%v", raw)
	}
	_, err := Parse(map[string]any{}, Defaults{Group: "auto"}, nil)
	assert.Error(t, err, "a group without url")
}

func TestAsksDestination(t *testing.T) {
	head := &Profile{URL: groupURL, Destination: groupURL, Method: MethodHEAD, Timeout: time.Second}
	assert.False(t, head.AsksDestination(), "a HEAD to the url itself repeats the delay test")
	assert.Equal(t, 5*time.Second, head.CheckTimeout(5*time.Second))

	get := &Profile{URL: groupURL, Destination: groupURL, Method: MethodGET, Timeout: time.Second}
	assert.True(t, get.AsksDestination())
	assert.Equal(t, 6*time.Second, get.CheckTimeout(5*time.Second))

	other := &Profile{URL: groupURL, Destination: "https://example.com/", Method: MethodHEAD}
	assert.True(t, other.AsksDestination())
}

func TestHistoryLimitHoldsTheWindow(t *testing.T) {
	assert.Equal(t, 10, (&Profile{Sampling: 1}).HistoryLimit(10))
	assert.Equal(t, 10, (&Profile{Sampling: 4}).HistoryLimit(10))
	assert.Equal(t, 13, (&Profile{Sampling: 6}).HistoryLimit(10))
}

func TestDailyTraffic(t *testing.T) {
	p := &Profile{Method: MethodGET, Interval: 15 * time.Second}
	assert.Equal(t, int64(0), p.DailyTraffic(20), "nothing read yet")
	p.NoteBody(51200)
	p.NoteBody(100) // the largest body counts
	assert.Equal(t, int64(51200*20*5760), p.DailyTraffic(20))
	assert.Equal(t, int64(0), (&Profile{Method: MethodHEAD, Interval: time.Second}).DailyTraffic(20))

	assert.True(t, p.WarnOnce())
	assert.False(t, p.WarnOnce())
}

func TestProfileJSON(t *testing.T) {
	p, err := Parse(map[string]any{"interval": "15s", "timeout": "3s", "http-method": "GET", "sampling": 2}, defaults(), nil)
	require.NoError(t, err)
	body, err := json.Marshal(p)
	require.NoError(t, err)
	assert.JSONEq(t, `{"destination":"`+groupURL+`","interval":15,"sampling":2,"timeout":3000,"httpMethod":"GET"}`, string(body))

	p.Connectivity = "http://example.com/"
	body, err = json.Marshal(p)
	require.NoError(t, err)
	assert.Contains(t, string(body), `"connectivity":"http://example.com/"`)
}

// One profile per url: the first stays, a different second one is a
// conflict, an identical one is not.
func TestRegistryKeepsTheFirstProfile(t *testing.T) {
	r := NewRegistry()
	first, err := Parse(map[string]any{"http-method": "GET"}, Defaults{Group: "a", URL: groupURL}, nil)
	require.NoError(t, err)
	same, err := Parse(map[string]any{"http-method": "GET"}, Defaults{Group: "b", URL: groupURL}, nil)
	require.NoError(t, err)
	other, err := Parse(map[string]any{"http-method": "HEAD"}, Defaults{Group: "c", URL: groupURL}, nil)
	require.NoError(t, err)

	kept, conflict := r.Add(first)
	assert.Same(t, first, kept)
	assert.False(t, conflict)
	kept, conflict = r.Add(same)
	assert.Same(t, first, kept)
	assert.False(t, conflict)
	kept, conflict = r.Add(other)
	assert.Same(t, first, kept)
	assert.True(t, conflict)
	assert.Equal(t, 1, r.Len())
	assert.Same(t, first, r.Lookup(groupURL))
	assert.Nil(t, r.Lookup("https://example.com/"))
}

func TestActiveRegistry(t *testing.T) {
	defer SetActive(nil)
	assert.Nil(t, Lookup(groupURL), "no config applied")

	r := NewRegistry()
	p := &Profile{URL: groupURL}
	r.Add(p)
	SetActive(r)
	assert.Same(t, p, Lookup(groupURL))

	SetActive(NewRegistry()) // a reload replaces it whole
	assert.Nil(t, Lookup(groupURL))
}

// A node is scheduled by one owner at a url; the claim moves when the
// owner lets go of it.
func TestClaims(t *testing.T) {
	a, b := new(int), new(int)
	node, other := new(int), new(int)
	defer Release(a)
	defer Release(b)

	assert.True(t, Claim(a, node, groupURL))
	assert.True(t, Claim(a, node, groupURL), "the owner keeps it")
	assert.False(t, Claim(b, node, groupURL))
	assert.True(t, Claim(b, node, "https://example.com/"), "another url is another claim")
	assert.True(t, Claim(a, other, groupURL))

	Retain(a, groupURL, map[any]struct{}{other: {}})
	assert.True(t, Claim(b, node, groupURL), "a dropped the node")
	assert.False(t, Claim(b, other, groupURL))

	Release(a)
	assert.True(t, Claim(b, other, groupURL))
}

// The plan checks every node Sampling times, the k-th time within the
// k-th interval, in time order; the same seed lays out the same plan.
func TestPlan(t *testing.T) {
	p := &Profile{Interval: 10 * time.Second, Sampling: 3}
	slots := Plan(5, p, rand.New(rand.NewSource(1)))
	require.Len(t, slots, 15)
	seen := map[int][]time.Duration{}
	for i, s := range slots {
		if i > 0 {
			assert.LessOrEqual(t, slots[i-1].Offset, s.Offset)
		}
		seen[s.Node] = append(seen[s.Node], s.Offset)
	}
	require.Len(t, seen, 5)
	for node, offsets := range seen {
		require.Len(t, offsets, 3, "node %d", node)
		for k, offset := range offsets {
			assert.GreaterOrEqual(t, offset, time.Duration(k)*p.Interval, "node %d sample %d", node, k)
			assert.Less(t, offset, time.Duration(k+1)*p.Interval, "node %d sample %d", node, k)
		}
	}
	assert.Equal(t, slots, Plan(5, p, rand.New(rand.NewSource(1))))
	assert.NotEqual(t, slots, Plan(5, p, rand.New(rand.NewSource(2))))
	assert.Empty(t, Plan(0, p, rand.New(rand.NewSource(1))))
}

func TestWindowStats(t *testing.T) {
	now := time.Now()
	at := func(ago time.Duration, delay uint16) C.DelayHistory {
		return C.DelayHistory{Time: now.Add(-ago), Delay: delay}
	}
	window := time.Minute

	alive, delay := WindowStats(nil, now, window)
	assert.False(t, alive)
	assert.Zero(t, delay)

	// one success in the window keeps the node, its delay the mean of the successes
	alive, delay = WindowStats([]C.DelayHistory{at(50*time.Second, 100), at(30*time.Second, 0), at(10*time.Second, 200)}, now, window)
	assert.True(t, alive)
	assert.Equal(t, uint16(150), delay)

	alive, _ = WindowStats([]C.DelayHistory{at(50*time.Second, 0), at(10*time.Second, 0)}, now, window)
	assert.False(t, alive)

	// results older than the window do not count
	alive, delay = WindowStats([]C.DelayHistory{at(2*time.Minute, 90), at(5*time.Second, 0)}, now, window)
	assert.False(t, alive)
	assert.Zero(t, delay)

	// with nothing in the window, the last result decides
	alive, delay = WindowStats([]C.DelayHistory{at(5*time.Minute, 0), at(3*time.Minute, 80)}, now, window)
	assert.True(t, alive)
	assert.Equal(t, uint16(80), delay)
}

// The device's network is asked once per connectivityTTL, however many
// checks fail at once.
func TestOnlineIsShared(t *testing.T) {
	var probes atomic.Int32
	probe := func() error {
		probes.Add(1)
		return errors.New("offline")
	}
	// the cache is the process's: a url of this run alone
	url := fmt.Sprintf("http://connectivity.test/shared-%d", time.Now().UnixNano())
	for i := 0; i < 5; i++ {
		assert.False(t, Online(url, probe))
	}
	assert.Equal(t, int32(1), probes.Load())

	assert.True(t, Online(url+"-other", func() error { return nil }))

	time.Sleep(connectivityTTL + 100*time.Millisecond)
	assert.False(t, Online(url, probe))
	assert.Equal(t, int32(2), probes.Load())
}
