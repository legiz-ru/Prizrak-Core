package xhttp

import (
	"io"
	"net"
	"testing"

	"github.com/metacubex/http"
	"github.com/metacubex/http/httptest"
	"github.com/stretchr/testify/assert"
)

func TestServerHandlerModeRestrictions(t *testing.T) {
	testCases := []struct {
		name       string
		mode       string
		method     string
		target     string
		wantStatus int
	}{
		{
			name:       "StreamOneAcceptsStreamOne",
			mode:       "stream-one",
			method:     http.MethodPost,
			target:     "https://example.com/xhttp/",
			wantStatus: http.StatusOK,
		},
		{
			name:       "StreamOneRejectsSessionDownload",
			mode:       "stream-one",
			method:     http.MethodGet,
			target:     "https://example.com/xhttp/session",
			wantStatus: http.StatusNotFound,
		},
		{
			name:       "StreamUpAcceptsStreamOne",
			mode:       "stream-up",
			method:     http.MethodPost,
			target:     "https://example.com/xhttp/",
			wantStatus: http.StatusOK,
		},
		{
			name:       "StreamUpAllowsDownloadEndpoint",
			mode:       "stream-up",
			method:     http.MethodGet,
			target:     "https://example.com/xhttp/session",
			wantStatus: http.StatusOK,
		},
		{
			name:       "StreamUpRejectsPacketUpload",
			mode:       "stream-up",
			method:     http.MethodPost,
			target:     "https://example.com/xhttp/session/0",
			wantStatus: http.StatusNotFound,
		},
		{
			name:       "PacketUpAllowsDownloadEndpoint",
			mode:       "packet-up",
			method:     http.MethodGet,
			target:     "https://example.com/xhttp/session",
			wantStatus: http.StatusOK,
		},
		{
			name:       "PacketUpRejectsStreamOne",
			mode:       "packet-up",
			method:     http.MethodPost,
			target:     "https://example.com/xhttp/",
			wantStatus: http.StatusNotFound,
		},
		{
			name:       "PacketUpRejectsStreamUpUpload",
			mode:       "packet-up",
			method:     http.MethodPost,
			target:     "https://example.com/xhttp/session",
			wantStatus: http.StatusNotFound,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			config := Config{
				Path: "/xhttp",
				Mode: testCase.mode,
			}
			handler, err := NewServerHandler(ServerOption{
				Config: config,
				ConnHandler: func(conn net.Conn) {
					_ = conn.Close()
				},
			})
			assert.NoError(t, err)

			req := httptest.NewRequest(testCase.method, testCase.target, io.NopCloser(http.NoBody))
			recorder := httptest.NewRecorder()

			err = config.FillStreamRequest(req, "")
			assert.NoError(t, err)

			handler.ServeHTTP(recorder, req)

			assert.Equal(t, testCase.wantStatus, recorder.Result().StatusCode)
		})
	}
}

// uplink-http-method may be GET: as in Xray, a request with a seq is a
// packet-up upload whatever its method, and a request without a session is
// stream-one whatever its method.
func TestServerHandlerAcceptsGETUplink(t *testing.T) {
	for _, placement := range []string{"body", "header", "cookie"} {
		t.Run("packet-up/"+placement, func(t *testing.T) {
			config := Config{Path: "/xhttp", Mode: "packet-up", UplinkHTTPMethod: http.MethodGet, UplinkDataPlacement: placement}
			var got []byte
			done := make(chan struct{})
			handler, err := NewServerHandler(ServerOption{
				Config: config,
				ConnHandler: func(conn net.Conn) {
					buf := make([]byte, 64)
					n, _ := conn.Read(buf)
					got = buf[:n]
					_ = conn.Close()
					close(done)
				},
			})
			assert.NoError(t, err)

			upload := httptest.NewRequest(http.MethodGet, "https://example.com/xhttp/", io.NopCloser(http.NoBody))
			assert.NoError(t, config.FillPacketRequest(upload, "session", "0", []byte("hello")))
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, upload)
			assert.Equal(t, http.StatusOK, recorder.Result().StatusCode)

			download := httptest.NewRequest(http.MethodGet, "https://example.com/xhttp/", io.NopCloser(http.NoBody))
			assert.NoError(t, config.FillDownloadRequest(download, "session"))
			go handler.ServeHTTP(httptest.NewRecorder(), download)
			<-done
			assert.Equal(t, "hello", string(got))
		})
	}

	t.Run("stream-one", func(t *testing.T) {
		config := Config{Path: "/xhttp", Mode: "stream-one"}
		handler, err := NewServerHandler(ServerOption{
			Config:      config,
			ConnHandler: func(conn net.Conn) { _ = conn.Close() },
		})
		assert.NoError(t, err)
		req := httptest.NewRequest(http.MethodGet, "https://example.com/xhttp/", io.NopCloser(http.NoBody))
		assert.NoError(t, config.FillStreamRequest(req, ""))
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, req)
		assert.Equal(t, http.StatusOK, recorder.Result().StatusCode)
	})
}

func TestUplinkDefaultsMatchXray(t *testing.T) {
	// Without a key the data travels under Xray's names.
	assert.Equal(t, "X-Data", (&Config{UplinkDataPlacement: "header"}).GetNormalizedUplinkDataKey())
	assert.Equal(t, "x_data", (&Config{UplinkDataPlacement: "cookie"}).GetNormalizedUplinkDataKey())
	assert.Equal(t, "X-Data", (&Config{}).GetNormalizedUplinkDataKey())
	assert.Equal(t, "X-Mine", (&Config{UplinkDataPlacement: "cookie", UplinkDataKey: "X-Mine"}).GetNormalizedUplinkDataKey())

	// The method is upper-cased, and GET is a packet-up thing.
	assert.Equal(t, "GET", (&Config{UplinkHTTPMethod: "get"}).GetNormalizedUplinkHTTPMethod())
	assert.NoError(t, (&Config{UplinkHTTPMethod: "get", Mode: "packet-up"}).CheckUplinkHTTPMethod())
	assert.Error(t, (&Config{UplinkHTTPMethod: "GET"}).CheckUplinkHTTPMethod())
	assert.Error(t, (&Config{UplinkHTTPMethod: "GET", Mode: "stream-up"}).CheckUplinkHTTPMethod())
	assert.NoError(t, (&Config{UplinkHTTPMethod: "PUT", Mode: "stream-up"}).CheckUplinkHTTPMethod())

	// Uploads in headers or cookies are small unless told otherwise.
	r, err := (&Config{UplinkDataPlacement: "header"}).GetNormalizedUploadScMaxEachPostBytes()
	assert.NoError(t, err)
	assert.Equal(t, 4*1024, r.Max)
	r, err = (&Config{UplinkDataPlacement: "cookie", ScMaxEachPostBytes: "4096"}).GetNormalizedUploadScMaxEachPostBytes()
	assert.NoError(t, err)
	assert.Equal(t, 4096, r.Max)
	r, err = (&Config{}).GetNormalizedUploadScMaxEachPostBytes()
	assert.NoError(t, err)
	assert.Equal(t, 1000000, r.Max)
}
