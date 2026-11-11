package xhttp

import (
	"context"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/common/httputils"

	"github.com/metacubex/http"
	"github.com/stretchr/testify/assert"
)

// h2CoalescedTransport is the HTTP/2 transport as NewClient uses it, with
// CoalesceDials on.
func h2CoalescedTransport(dialRaw DialRawFunc, wrapTLS WrapTLSFunc) http.RoundTripper {
	return CoalesceDials(func() http.RoundTripper {
		return NewTransport(dialRaw, wrapTLS, nil, nil, 0, nil)
	})()
}

func h2TestRequests(tr http.RoundTripper, n int, timeout time.Duration) int32 {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	var wg sync.WaitGroup
	var ok atomic.Int32
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://localhost/", nil)
			if err != nil {
				return
			}
			if resp, err := tr.RoundTrip(req); err == nil {
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
				ok.Add(1)
			}
		}()
	}
	wg.Wait()
	return ok.Load()
}

// While a TLS handshake hangs, for example because a censor drops the flow
// after the ClientHello, the requests waiting for HTTP/2 share one dial
// (XTLS/Xray-core#6797) instead of opening a connection each.
func TestH2ClientSharesOneDialWhileHandshakeHangs(t *testing.T) {
	var dials atomic.Int32
	tr := h2CoalescedTransport(func(ctx context.Context) (net.Conn, error) {
		dials.Add(1)
		a, b := net.Pipe()
		go func() { _, _ = io.Copy(io.Discard, b) }()
		return a, nil
	}, func(ctx context.Context, c net.Conn, isH2 bool) (net.Conn, error) {
		<-ctx.Done() // the handshake never completes
		_ = c.Close()
		return nil, ctx.Err()
	})
	defer closeTestTransport(tr)

	assert.Zero(t, h2TestRequests(tr, 16, 500*time.Millisecond))
	assert.EqualValues(t, 1, dials.Load(), "16 requests waiting on a hung handshake must open one connection")
}

// Requests that start together on a fresh transport share one HTTP/2
// connection; more are dialed only when the server's stream limit is reached.
// Those dials are coalesced too, but a request that retries while another one
// has just taken the place of the leader may dial once more, so the stream
// limit case allows up to twice the four connections it needs: 5 or 6 are
// common and 7 or 8 come about once in 300 runs, while a dial per request
// would make 16 (upstream's TestCoalesceDialsStreamLimit allows 10 for 6).
func TestH2ClientBurstOpensOneConnection(t *testing.T) {
	for _, tc := range []struct {
		streams  uint32
		min, max int32
	}{{0, 1, 1}, {4, 4, 8}} {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		assert.NoError(t, err)
		// every request holds its stream until all 16 are in, so the
		// connections needed do not depend on how fast the machine is
		var arrived atomic.Int32
		release := make(chan struct{})
		srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if arrived.Add(1) == 16 {
				close(release)
			}
			select {
			case <-release:
			case <-time.After(3 * time.Second):
			}
			_, _ = w.Write([]byte("ok"))
		})}
		srv.Protocols = new(http.Protocols)
		srv.Protocols.SetUnencryptedHTTP2(true)
		srv.HTTP2 = &http.HTTP2Config{MaxConcurrentStreams: int(tc.streams)}
		go func() { _ = srv.Serve(ln) }()

		var dials atomic.Int32
		tr := h2CoalescedTransport(func(ctx context.Context) (net.Conn, error) {
			dials.Add(1)
			var d net.Dialer
			return d.DialContext(ctx, "tcp", ln.Addr().String())
		}, func(ctx context.Context, c net.Conn, isH2 bool) (net.Conn, error) { return c, nil })

		assert.EqualValues(t, 16, h2TestRequests(tr, 16, 5*time.Second))
		got := dials.Load()
		assert.True(t, got >= tc.min && got <= tc.max, "server stream limit %d: %d dials, want %d..%d", tc.streams, got, tc.min, tc.max)
		closeTestTransport(tr)
		_ = srv.Close()
	}
}

func closeTestTransport(tr http.RoundTripper) {
	httputils.CloseTransport(tr)
}

// A packet-up POST can be sent again: HTTP/2 replays it on a new connection
// when a GOAWAY retires the one it went out on (XTLS/Xray-core#6632).
func TestFillPacketRequestCanReplayBody(t *testing.T) {
	config := Config{}
	req, err := http.NewRequest(http.MethodPost, "https://example.com/", nil)
	assert.NoError(t, err)
	assert.NoError(t, config.FillPacketRequest(req, "session", "0", []byte("hello xhttp")))
	if !assert.NotNil(t, req.GetBody) {
		return
	}
	first, err := io.ReadAll(req.Body)
	assert.NoError(t, err)
	again, err := req.GetBody()
	assert.NoError(t, err)
	second, err := io.ReadAll(again)
	assert.NoError(t, err)
	assert.Equal(t, "hello xhttp", string(first))
	assert.Equal(t, string(first), string(second))
}
