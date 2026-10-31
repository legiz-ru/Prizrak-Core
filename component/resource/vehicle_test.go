package resource

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/component/profile/cachefile"
	C "github.com/metacubex/mihomo/constant"

	mhttp "github.com/metacubex/http"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "vehicle-test")
	if err != nil {
		panic(err)
	}
	C.SetHomeDir(dir)
	code := m.Run()
	cachefile.Cache().Close()
	os.RemoveAll(dir)
	os.Exit(code)
}

// mirror is a test address answering with a status and a body, counting
// the requests it got.
type mirror struct {
	*httptest.Server
	hits atomic.Int32
}

func newMirror(t *testing.T, handler http.HandlerFunc) *mirror {
	m := &mirror{}
	m.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.hits.Add(1)
		handler(w, r)
	}))
	t.Cleanup(m.Close)
	return m
}

func status(code int, body string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(code)
		_, _ = w.Write([]byte(body))
	}
}

// closedURL is an address nothing listens on.
func closedURL(t *testing.T) string {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := l.Addr().String()
	require.NoError(t, l.Close())
	return "http://" + addr + "/rules.yaml"
}

func vehicle(main string, timeout time.Duration, fallbacks ...string) *HTTPVehicle {
	var options []HTTPVehicleOption
	if len(fallbacks) > 0 {
		options = append(options, WithFallbackURLs("test", fallbacks))
	}
	return NewHTTPVehicle(main, "", "", nil, timeout, 0, options...)
}

func TestHTTPVehicleFallbackOnServerError(t *testing.T) {
	main := newMirror(t, status(500, "main"))
	backup := newMirror(t, status(200, "backup"))
	buf, _, err := vehicle(main.URL, time.Second, backup.URL).Read(context.Background(), utils.HashType{})
	require.NoError(t, err)
	assert.Equal(t, "backup", string(buf))
	assert.EqualValues(t, 1, main.hits.Load())
}

func TestHTTPVehicleFallbackOnClosedPort(t *testing.T) {
	backup := newMirror(t, status(200, "backup"))
	h := vehicle(closedURL(t), time.Second, backup.URL)
	buf, _, err := h.Read(context.Background(), utils.HashType{})
	require.NoError(t, err)
	assert.Equal(t, "backup", string(buf))
	assert.Equal(t, backup.URL, h.LastURL())
}

func TestHTTPVehicleFallbackInOrder(t *testing.T) {
	main := newMirror(t, status(404, "main"))
	first := newMirror(t, status(502, "first"))
	second := newMirror(t, status(200, "second"))
	buf, _, err := vehicle(main.URL, time.Second, first.URL, second.URL).Read(context.Background(), utils.HashType{})
	require.NoError(t, err)
	assert.Equal(t, "second", string(buf))
	assert.EqualValues(t, 1, main.hits.Load())
	assert.EqualValues(t, 1, first.hits.Load())
	assert.EqualValues(t, 1, second.hits.Load())
}

func TestHTTPVehicleAllFail(t *testing.T) {
	main := newMirror(t, status(500, ""))
	backup := newMirror(t, status(403, ""))
	_, _, err := vehicle(main.URL+"/sub?token=secret", time.Second, backup.URL+"/sub?token=secret").Read(context.Background(), utils.HashType{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), main.URL+"/sub: 500")
	assert.Contains(t, err.Error(), backup.URL+"/sub: 403")
	closed := closedURL(t)
	_, _, err = vehicle(closed+"?token=secret", time.Second, backup.URL).Read(context.Background(), utils.HashType{})
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "secret")
}

func withETag(t *testing.T) {
	old := ETag()
	SetETag(true)
	t.Cleanup(func() { SetETag(old) })
}

func etagHandler(tag, body string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") == tag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", tag)
		_, _ = w.Write([]byte(body))
	}
}

// 304 from the main address keeps the old data and asks no fallback.
func TestHTTPVehicleNotModifiedStops(t *testing.T) {
	withETag(t)
	main := newMirror(t, etagHandler(`"main-v1"`, "main"))
	backup := newMirror(t, status(200, "backup"))
	h := vehicle(main.URL+"/304", time.Second, backup.URL)
	buf, hash, err := h.Read(context.Background(), utils.HashType{})
	require.NoError(t, err)
	require.Equal(t, "main", string(buf))

	buf, newHash, err := h.Read(context.Background(), hash)
	require.NoError(t, err)
	assert.Nil(t, buf)
	assert.True(t, hash.Equal(newHash))
	assert.EqualValues(t, 2, main.hits.Load())
	assert.EqualValues(t, 0, backup.hits.Load())
}

// The ETag lives under the address that answered, the main one keeping
// its old key.
func TestHTTPVehicleETagPerAddress(t *testing.T) {
	withETag(t)
	fail := atomic.Bool{}
	main := newMirror(t, func(w http.ResponseWriter, r *http.Request) {
		if fail.Load() {
			w.WriteHeader(500)
			return
		}
		etagHandler(`"main-v1"`, "data")(w, r)
	})
	backup := newMirror(t, etagHandler(`"backup-v1"`, "data"))
	mainURL, backupURL := main.URL+"/etag", backup.URL+"/etag"
	h := vehicle(mainURL, time.Second, backupURL)

	_, hash, err := h.Read(context.Background(), utils.HashType{})
	require.NoError(t, err)
	assert.Equal(t, `"main-v1"`, cachefile.Cache().GetETagWithHash(mainURL).ETag)
	assert.Empty(t, cachefile.Cache().GetETagWithHash(backupURL).ETag)

	fail.Store(true)
	buf, _, err := h.Read(context.Background(), hash)
	require.NoError(t, err)
	assert.Equal(t, "data", string(buf))
	assert.Equal(t, `"backup-v1"`, cachefile.Cache().GetETagWithHash(backupURL).ETag)
	assert.Equal(t, `"main-v1"`, cachefile.Cache().GetETagWithHash(mainURL).ETag)

	// The backup's own ETag now answers 304 there.
	buf, newHash, err := h.Read(context.Background(), hash)
	require.NoError(t, err)
	assert.Nil(t, buf)
	assert.True(t, hash.Equal(newHash))
}

// Every attempt has a timeout of its own.
func TestHTTPVehicleTimeoutPerAttempt(t *testing.T) {
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	hang := newMirror(t, func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	})
	backup := newMirror(t, func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		_, _ = w.Write([]byte("backup"))
	})
	timeout := 500 * time.Millisecond
	start := time.Now()
	buf, _, err := vehicle(hang.URL, timeout, backup.URL).Read(context.Background(), utils.HashType{})
	elapsed := time.Since(start)
	require.NoError(t, err)
	assert.Equal(t, "backup", string(buf))
	assert.GreaterOrEqual(t, elapsed, timeout)
	assert.Less(t, elapsed, timeout+200*time.Millisecond+500*time.Millisecond)
}

// A cancelled read tries no further address.
func TestHTTPVehicleCancelStops(t *testing.T) {
	backup := newMirror(t, status(200, "backup"))
	hang := newMirror(t, func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() })
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_, _, err := vehicle(hang.URL, 5*time.Second, backup.URL).Read(ctx, utils.HashType{})
	require.Error(t, err)
	assert.EqualValues(t, 0, backup.hits.Load())
}

// inRead sees the response of the address that answered.
func TestHTTPVehicleInReadAnsweringAddress(t *testing.T) {
	main := newMirror(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-From", "main")
		w.WriteHeader(500)
	})
	backup := newMirror(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-From", "backup")
		_, _ = w.Write([]byte("backup"))
	})
	var seen []string
	h := vehicle(main.URL, time.Second, backup.URL)
	h.SetInRead(func(resp *mhttp.Response) { seen = append(seen, resp.Header.Get("X-From")) })
	_, _, err := h.Read(context.Background(), utils.HashType{})
	require.NoError(t, err)
	assert.Equal(t, []string{"backup"}, seen)
}

// Without fallback-urls a read is one request, inRead seeing it whatever
// it answered, as before.
func TestHTTPVehicleWithoutFallback(t *testing.T) {
	main := newMirror(t, status(500, "main"))
	var seen int
	h := NewHTTPVehicle(main.URL, "", "", nil, time.Second, 0)
	h.SetInRead(func(resp *mhttp.Response) { seen++ })
	_, _, err := h.Read(context.Background(), utils.HashType{})
	require.EqualError(t, err, "500 Internal Server Error")
	assert.EqualValues(t, 1, main.hits.Load())
	assert.Equal(t, 1, seen)
	assert.Empty(t, h.LastURL())
}

func TestParseFallbackURLs(t *testing.T) {
	urls, err := ParseFallbackURLs("https://a.example/x", []string{
		"", " ", "https://a.example/x", "https://b.example/x", "http://c.example/x", "https://b.example/x",
	})
	require.NoError(t, err)
	assert.Equal(t, []string{"https://b.example/x", "http://c.example/x"}, urls)

	urls, err = ParseFallbackURLs("https://a.example/x", nil)
	require.NoError(t, err)
	assert.Empty(t, urls)

	for _, bad := range []string{"ftp://b.example/x", "b.example/x", "https://", "file:///etc/hosts", "http://b.example/%zz"} {
		_, err := ParseFallbackURLs("https://a.example/x", []string{bad})
		assert.Error(t, err, bad)
	}
	_, err = ParseFallbackURLs("", []string{"https://b.example/x?token=secret", "ftp://c.example/x?token=secret"})
	require.Error(t, err)
	assert.False(t, strings.Contains(err.Error(), "secret"), err.Error())
}
