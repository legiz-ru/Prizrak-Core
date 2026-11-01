package xhttp

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/metacubex/http"
	"github.com/metacubex/http/httptest"
	"github.com/stretchr/testify/assert"
)

// uplink-http-method may be OPTIONS (XTLS/Xray-core#7290): an OPTIONS
// request is a CORS preflight only when it carries
// Access-Control-Request-Method, and an upload otherwise.
func TestServerHandlerAcceptsOPTIONSUplink(t *testing.T) {
	config := Config{Path: "/xhttp", Mode: "packet-up", UplinkHTTPMethod: http.MethodOptions}
	got := make(chan string, 1)
	handler, err := NewServerHandler(ServerOption{
		Config: config,
		ConnHandler: func(conn net.Conn) {
			buf := make([]byte, 64)
			n, _ := conn.Read(buf)
			got <- string(buf[:n])
			_ = conn.Close()
		},
	})
	assert.NoError(t, err)

	preflight := httptest.NewRequest(http.MethodOptions, "https://example.com/xhttp/", nil)
	preflight.Header.Set("Origin", "https://example.com")
	preflight.Header.Set("Access-Control-Request-Method", http.MethodOptions)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, preflight)
	assert.Equal(t, http.StatusOK, recorder.Result().StatusCode)
	assert.Equal(t, http.MethodOptions, recorder.Result().Header.Get("Access-Control-Allow-Methods"))

	upload := httptest.NewRequest(http.MethodOptions, "https://example.com/xhttp/", nil)
	assert.NoError(t, config.FillPacketRequest(upload, "session", "0", []byte("hello")))
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, upload)
	assert.Equal(t, http.StatusOK, recorder.Result().StatusCode)

	download := httptest.NewRequest(http.MethodGet, "https://example.com/xhttp/", io.NopCloser(http.NoBody))
	assert.NoError(t, config.FillDownloadRequest(download, "session"))
	go handler.ServeHTTP(httptest.NewRecorder(), download)
	select {
	case data := <-got:
		assert.Equal(t, "hello", data)
	case <-time.After(5 * time.Second):
		t.Fatal("the OPTIONS upload never reached the session")
	}
}
