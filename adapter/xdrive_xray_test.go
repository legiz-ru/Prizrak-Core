package adapter

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

// VLESS over XDRIVE against Xray-core v26.11.9 or later, as a client of
// the same storage the server of the test watches: a folder and an HTTP
// storage described by a template.
//
//	XRAY_BIN=/path/to/xray go test ./adapter/ -run TestXrayXDrive -v

const (
	xdriveTestDecryption = "mlkem768x25519plus.native.600s.aM_chHIK2NV4dGlPITIwJBhy_w8NmIxNjXYd5t80TUg"
	xdriveTestEncryption = "mlkem768x25519plus.native.0rtt.gWPtAUIX9CGNQhiWit9Zty9ryz8kQKMiXkzjtC_sxSA"
)

// xdriveStore is a storage for service: template, flat over HTTP.
type xdriveStore struct {
	mu      sync.Mutex
	objects map[string][]byte
}

func newXDriveStore(t *testing.T) (*httptest.Server, map[string]any) {
	t.Helper()
	store := &xdriveStore{objects: map[string][]byte{}}
	server := httptest.NewServer(store)
	t.Cleanup(server.Close)
	base := server.URL
	return server, map[string]any{
		"put":    map[string]any{"method": "PUT", "url": base + "/{folder}/{name}"},
		"get":    map[string]any{"method": "GET", "url": base + "/{folder}/{name}"},
		"delete": map[string]any{"method": "DELETE", "url": base + "/{folder}/{name}"},
		"list":   map[string]any{"method": "GET", "url": base + "/_list?prefix={folder}/{prefix}", "namesRegex": `"([^"]+)"`},
		"retry":  map[string]any{"status": []any{429, 503}},
	}
}

func (s *xdriveStore) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case r.Method == "GET" && name == "_list":
		prefix := strings.TrimSuffix(r.URL.Query().Get("prefix"), "/") + "/"
		seen := map[string]bool{}
		names := []string{}
		for key := range s.objects {
			if strings.HasPrefix(key, prefix) {
				child, _, _ := strings.Cut(strings.TrimPrefix(key, prefix), "/")
				if child != "" && !seen[child] {
					seen[child] = true
					names = append(names, `"`+child+`"`)
				}
			}
		}
		_, _ = io.WriteString(w, "["+strings.Join(names, ",")+"]")
	case r.Method == "PUT":
		data, _ := io.ReadAll(r.Body)
		s.objects[name] = data
	case r.Method == "GET":
		data, ok := s.objects[name]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write(data)
	case r.Method == "DELETE":
		for key := range s.objects {
			if key == name || strings.HasPrefix(key, name+"/") {
				delete(s.objects, key)
			}
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func TestXrayXDrive(t *testing.T) {
	bin := xrayBinary(t)
	echoPort := echoServer(t)

	cases := []struct {
		name     string
		settings func(t *testing.T) map[string]any
		opts     func(settings map[string]any) map[string]any
	}{
		{
			name: "local",
			settings: func(t *testing.T) map[string]any {
				return map[string]any{"service": "local", "remoteFolder": homeTempDir(t)}
			},
			opts: func(settings map[string]any) map[string]any {
				return map[string]any{"service": "local", "remote-folder": settings["remoteFolder"]}
			},
		},
		{
			name: "template",
			settings: func(t *testing.T) map[string]any {
				_, template := newXDriveStore(t)
				return map[string]any{"service": "template", "remoteFolder": "xdrive-test", "template": template}
			},
			opts: func(settings map[string]any) map[string]any {
				return map[string]any{"service": "template", "remote-folder": settings["remoteFolder"], "template": settings["template"]}
			},
		},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			settings := c.settings(t)
			startXray(t, bin, xrayServer{
				proto:      "vless",
				decryption: xdriveTestDecryption,
				stream:     map[string]any{"network": "xdrive", "xdriveSettings": settings},
				port:       freePort(t, "tcp"),
				network:    "tcp",
				readyTCP:   freePort(t, "tcp"),
			})
			proxy, err := ParseProxy(map[string]any{
				"name": "vless-xdrive", "type": "vless", "server": "127.0.0.1", "port": 443, "uuid": xrayUUID,
				"encryption": xdriveTestEncryption, "network": "xdrive", "udp": true,
				"mux.cool":    map[string]any{"enabled": true},
				"xdrive-opts": c.opts(settings),
			})
			require.NoError(t, err)
			defer proxy.Close()
			echoThrough(t, proxy, echoPort, 256*1024)
		})
	}
}

func TestParseProxyXDriveChecks(t *testing.T) {
	base := func() map[string]any {
		return map[string]any{
			"name": "xd", "type": "vless", "server": "127.0.0.1", "port": 443, "uuid": xrayUUID,
			"encryption": xdriveTestEncryption, "network": "xdrive",
			"mux.cool":    map[string]any{"enabled": true},
			"xdrive-opts": map[string]any{"service": "local", "remote-folder": "xdrive"},
		}
	}
	proxy, err := ParseProxy(base())
	require.NoError(t, err)
	_ = proxy.Close()

	for name, change := range map[string]func(m map[string]any){
		"no mux":        func(m map[string]any) { delete(m, "mux.cool") },
		"mux disabled":  func(m map[string]any) { m["mux.cool"] = map[string]any{"enabled": false} },
		"skip udp 443":  func(m map[string]any) { m["mux.cool"] = map[string]any{"enabled": true, "xudp-proxy-udp443": "skip"} },
		"no encryption": func(m map[string]any) { delete(m, "encryption") },
		"encrypt none":  func(m map[string]any) { m["encryption"] = "none" },
		"flow":          func(m map[string]any) { m["flow"] = "xtls-rprx-vision" },
		"no opts":       func(m map[string]any) { delete(m, "xdrive-opts") },
		"bad service":   func(m map[string]any) { m["xdrive-opts"] = map[string]any{"service": "ftp"} },
		// a subscription must not write wherever it likes
		"unsafe folder": func(m map[string]any) {
			m["xdrive-opts"] = map[string]any{"service": "local", "remote-folder": filepath.Join(os.TempDir(), "xdrive")}
		},
		"two secrets": func(m map[string]any) {
			m["xdrive-opts"] = map[string]any{"service": "google-drive", "remote-folder": "f", "secrets": []any{"a", "b"}}
		},
		"s3 no block": func(m map[string]any) {
			m["xdrive-opts"] = map[string]any{"service": "s3", "remote-folder": "f", "secrets": []any{"a", "b"}}
		},
		"template bad json": func(m map[string]any) {
			m["xdrive-opts"] = map[string]any{"service": "template", "remote-folder": "f", "template": "{"}
		},
		"reality": func(m map[string]any) {
			m["tls"] = true
			m["reality-opts"] = map[string]any{"public-key": "x", "short-id": "ab"}
		},
	} {
		m := base()
		change(m)
		_, err := ParseProxy(m)
		require.Error(t, err, name)
	}
}
