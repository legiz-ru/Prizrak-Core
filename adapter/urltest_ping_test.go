package adapter

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/component/pingconfig"
	C "github.com/metacubex/mihomo/constant"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// site is a test HTTP server that logs the method of every request.
type site struct {
	*httptest.Server
	mu       sync.Mutex
	requests []string
}

func newSite(t *testing.T, handler func(w http.ResponseWriter, r *http.Request), configure ...func(*http.Server)) *site {
	s := &site{}
	s.Server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.requests = append(s.requests, r.Method+" "+r.URL.Path)
		s.mu.Unlock()
		handler(w, r)
	}))
	for _, c := range configure {
		c(s.Config)
	}
	s.Start()
	t.Cleanup(s.Close)
	return s
}

func (s *site) log() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.requests...)
}

// body answers HEAD with 204 and GET with n bytes.
func body(n int) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		_, _ = w.Write([]byte(strings.Repeat("x", n)))
	}
}

func usePing(t *testing.T, profiles ...*pingconfig.Profile) {
	r := pingconfig.NewRegistry()
	for _, p := range profiles {
		r.Add(p)
	}
	pingconfig.SetActive(r)
	t.Cleanup(func() { pingconfig.SetActive(nil) })
}

func useUnifiedDelay(t *testing.T, on bool) {
	old := UnifiedDelay.Load()
	UnifiedDelay.Store(on)
	t.Cleanup(func() { UnifiedDelay.Store(old) })
}

func profile(url, destination, method string) *pingconfig.Profile {
	return &pingconfig.Profile{
		URL: url, Destination: destination, Method: method,
		Interval: time.Minute, Sampling: 1, Timeout: 2 * time.Second, Group: "auto",
	}
}

func direct() *Proxy {
	return NewProxy(outbound.NewDirect())
}

func urlTest(p *Proxy, url string) (uint16, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return p.URLTest(ctx, url, nil)
}

// Without a profile a delay test is the one HEAD it always was.
func TestURLTestWithoutPingConfigIsOneHead(t *testing.T) {
	useUnifiedDelay(t, false)
	s := newSite(t, body(10))
	url := s.URL + "/generate_204"
	p := direct()

	delay, err := urlTest(p, url)
	require.NoError(t, err)
	assert.NotZero(t, delay)
	assert.Equal(t, []string{"HEAD /generate_204"}, s.log())
	assert.True(t, p.AliveForTestUrl(url))
	assert.Len(t, p.DelayHistoryForTestUrl(url), 1)
}

// A GET destination on the url's own address goes over the test's
// connection after its HEAD; the delay is the HEAD's.
func TestURLTestGetsTheDestinationAfterTheHead(t *testing.T) {
	useUnifiedDelay(t, false)
	s := newSite(t, body(51200))
	url := s.URL + "/generate_204"
	pr := profile(url, s.URL+"/down", pingconfig.MethodGET)
	usePing(t, pr)
	p := direct()

	delay, err := urlTest(p, url)
	require.NoError(t, err)
	assert.NotZero(t, delay)
	assert.Equal(t, []string{"HEAD /generate_204", "GET /down"}, s.log())
	assert.True(t, p.AliveForTestUrl(url))
	assert.Equal(t, delay, p.LastDelayForTestUrl(url))
	assert.Equal(t, int64(51200*1440), pr.DailyTraffic(1), "the body read is counted for the traffic estimate")
}

// A node whose body stalls after the headers (as one cut by DPI after
// ~16-20 KB) fails the test, though its HEAD answered.
func TestURLTestFailsAStalledBody(t *testing.T) {
	useUnifiedDelay(t, false)
	release := make(chan struct{})
	defer close(release)
	s := newSite(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Header().Set("Content-Length", "51200")
		_, _ = w.Write([]byte(strings.Repeat("x", 20000)))
		w.(http.Flusher).Flush()
		select {
		case <-release:
		case <-r.Context().Done():
		}
	})
	url := s.URL + "/generate_204"
	pr := profile(url, s.URL+"/down", pingconfig.MethodGET)
	pr.Timeout = 300 * time.Millisecond
	usePing(t, pr)
	p := direct()

	start := time.Now()
	delay, err := urlTest(p, url)
	require.Error(t, err)
	assert.Zero(t, delay)
	assert.Less(t, time.Since(start), 2*time.Second, "the profile's timeout ends it")
	assert.False(t, p.AliveForTestUrl(url))
	assert.Equal(t, uint16(0xffff), p.LastDelayForTestUrl(url))
}

func TestURLTestFailsADestinationError(t *testing.T) {
	useUnifiedDelay(t, false)
	s := newSite(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/down" {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	url := s.URL + "/generate_204"
	usePing(t, profile(url, s.URL+"/down", pingconfig.MethodGET))
	p := direct()

	_, err := urlTest(p, url)
	assert.ErrorContains(t, err, "502")
	assert.False(t, p.AliveForTestUrl(url))
}

// A destination on another address is asked over a connection of its own,
// with the method of the profile.
func TestURLTestAsksAnotherDestinationWithItsMethod(t *testing.T) {
	useUnifiedDelay(t, false)
	s := newSite(t, body(10))
	dest := newSite(t, body(1000))
	url := s.URL + "/generate_204"
	usePing(t, profile(url, dest.URL+"/ok", pingconfig.MethodHEAD))
	p := direct()

	_, err := urlTest(p, url)
	require.NoError(t, err)
	assert.Equal(t, []string{"HEAD /generate_204"}, s.log())
	assert.Equal(t, []string{"HEAD /ok"}, dest.log())
	assert.True(t, p.AliveForTestUrl(url))

	// the destination down: the node fails though its url answers
	dest.Close()
	_, err = urlTest(p, url)
	assert.Error(t, err)
	assert.False(t, p.AliveForTestUrl(url))
}

// HEAD to the url itself would repeat the delay test: no second request.
func TestURLTestDoesNotRepeatTheHead(t *testing.T) {
	useUnifiedDelay(t, false)
	s := newSite(t, body(10))
	url := s.URL + "/generate_204"
	usePing(t, profile(url, url, pingconfig.MethodHEAD))

	_, err := urlTest(direct(), url)
	require.NoError(t, err)
	assert.Equal(t, []string{"HEAD /generate_204"}, s.log())
}

// With unified-delay the delay is the second HEAD's, and the GET follows
// on the same connection.
func TestURLTestUnifiedDelayThenGet(t *testing.T) {
	useUnifiedDelay(t, true)
	var conns sync.Map
	s := newSite(t, body(4096), func(server *http.Server) {
		server.ConnState = func(c net.Conn, state http.ConnState) {
			if state == http.StateNew {
				conns.Store(c.RemoteAddr().String(), true)
			}
		}
	})
	url := s.URL + "/generate_204"
	usePing(t, profile(url, url, pingconfig.MethodGET))

	_, err := urlTest(direct(), url)
	require.NoError(t, err)
	assert.Equal(t, []string{"HEAD /generate_204", "HEAD /generate_204", "GET /generate_204"}, s.log())
	n := 0
	conns.Range(func(any, any) bool { n++; return true })
	assert.Equal(t, 1, n, "one connection carries all three")
}

// When the site closes the connection after the HEAD, the GET goes over a
// new one and the node stays alive.
func TestURLTestRedialsWhenTheHeadClosedTheConnection(t *testing.T) {
	useUnifiedDelay(t, false)
	s := newSite(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			w.Header().Set("Connection", "close")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		_, _ = w.Write([]byte("ok"))
	})
	url := s.URL + "/generate_204"
	usePing(t, profile(url, url, pingconfig.MethodGET))
	p := direct()

	_, err := urlTest(p, url)
	require.NoError(t, err)
	assert.Equal(t, []string{"HEAD /generate_204", "GET /generate_204"}, s.log())
	assert.True(t, p.AliveForTestUrl(url))
}

// An unexpected status of the url fails the test before the destination.
func TestURLTestSkipsTheDestinationOnAnUnexpectedStatus(t *testing.T) {
	useUnifiedDelay(t, false)
	s := newSite(t, body(10))
	url := s.URL + "/generate_204"
	usePing(t, profile(url, s.URL+"/down", pingconfig.MethodGET))
	p := direct()

	expected, err := utils.NewUnsignedRanges[uint16]("200")
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _ = p.URLTest(ctx, url, expected)
	assert.Equal(t, []string{"HEAD /generate_204"}, s.log())
	assert.False(t, p.AliveForTestUrl(url))
}

// With connectivity set, a failure while the device is offline is not
// recorded; while it is online, it is.
func TestURLTestConnectivity(t *testing.T) {
	useUnifiedDelay(t, false)
	s := newSite(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/down" {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	url := s.URL + "/generate_204"

	closed, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	offline := "http://" + closed.Addr().String() + "/generate_204"
	require.NoError(t, closed.Close())

	pr := profile(url, s.URL+"/down", pingconfig.MethodGET)
	pr.Connectivity = offline
	usePing(t, pr)
	p := direct()

	_, err = urlTest(p, url)
	assert.Error(t, err)
	assert.Empty(t, p.DelayHistoryForTestUrl(url), "offline: nothing recorded")
	assert.True(t, p.AliveForTestUrl(url), "and the node is not taken for dead")

	online := newSite(t, body(0))
	pr.Connectivity = online.URL + "/generate_204"
	_, err = urlTest(p, url)
	assert.Error(t, err)
	assert.Len(t, p.DelayHistoryForTestUrl(url), 1)
	assert.False(t, p.AliveForTestUrl(url))
	assert.Equal(t, []string{"HEAD /generate_204"}, online.log())
}

// With sampling a node is alive while any result of the window succeeded,
// and its delay is the mean of those that did.
func TestURLTestSamplingWindow(t *testing.T) {
	useUnifiedDelay(t, false)
	fail := false
	var mu sync.Mutex
	s := newSite(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.URL.Path == "/down" && fail {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	url := s.URL + "/generate_204"
	pr := profile(url, s.URL+"/down", pingconfig.MethodGET)
	pr.Sampling = 3
	usePing(t, pr)
	p := direct()

	_, err := urlTest(p, url)
	require.NoError(t, err)
	mu.Lock()
	fail = true
	mu.Unlock()
	_, err = urlTest(p, url)
	require.Error(t, err)

	assert.True(t, p.AliveForTestUrl(url), "one success in the window")
	history := p.DelayHistoryForTestUrl(url)
	require.Len(t, history, 2)
	assert.Equal(t, history[0].Delay, p.LastDelayForTestUrl(url), "the mean of the one success")

	// the history holds the whole window: 2×sampling+1 results
	for i := 0; i < 12; i++ {
		_, _ = urlTest(p, url)
	}
	assert.Len(t, p.DelayHistoryForTestUrl(url), 10, "10 is more than 2×3+1")
	assert.False(t, p.AliveForTestUrl(url), "no success left in the history")
}

// healthCheckProbe is a direct proxy that records whether its dials are
// marked as health checks.
type healthCheckProbe struct {
	C.ProxyAdapter
	marked []bool
}

func (h *healthCheckProbe) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	h.marked = append(h.marked, C.IsHealthCheck(ctx))
	return h.ProxyAdapter.DialContext(ctx, metadata)
}

// The dials of a delay test carry the health check mark, those of the
// destination included.
func TestURLTestMarksItsDialsAsHealthChecks(t *testing.T) {
	useUnifiedDelay(t, false)
	s := newSite(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			w.Header().Set("Connection", "close")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		_, _ = w.Write([]byte("ok"))
	})
	url := s.URL + "/generate_204"
	usePing(t, profile(url, url, pingconfig.MethodGET))
	probe := &healthCheckProbe{ProxyAdapter: outbound.NewDirect()}
	p := NewProxy(probe)

	_, err := urlTest(p, url)
	require.NoError(t, err)
	require.Len(t, probe.marked, 2)
	for i, marked := range probe.marked {
		assert.True(t, marked, "dial %d", i)
	}
}
