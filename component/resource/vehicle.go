package resource

import (
	"context"
	"errors"
	"fmt"
	"io"
	URL "net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/common/utils"
	mihomoHttp "github.com/metacubex/mihomo/component/http"
	"github.com/metacubex/mihomo/component/profile/cachefile"
	P "github.com/metacubex/mihomo/constant/provider"
	"github.com/metacubex/mihomo/log"

	"github.com/metacubex/http"
)

const (
	DefaultHttpTimeout = time.Second * 20

	fileMode os.FileMode = 0o666
	dirMode  os.FileMode = 0o755
)

var (
	etag = false
)

func ETag() bool {
	return etag
}

func SetETag(b bool) {
	etag = b
}

func safeWrite(path string, buf []byte) error {
	dir := filepath.Dir(path)

	if _, err := os.Stat(dir); os.IsNotExist(err) {
		if err := os.MkdirAll(dir, dirMode); err != nil {
			return err
		}
	}

	return os.WriteFile(path, buf, fileMode)
}

type FileVehicle struct {
	path string
}

func (f *FileVehicle) Type() P.VehicleType {
	return P.File
}

func (f *FileVehicle) Path() string {
	return f.path
}

func (f *FileVehicle) Url() string {
	return "file://" + f.path
}

func (f *FileVehicle) Read(ctx context.Context, oldHash utils.HashType) (buf []byte, hash utils.HashType, err error) {
	buf, err = os.ReadFile(f.path)
	if err != nil {
		return
	}
	hash = utils.MakeHash(buf)
	return
}

func (f *FileVehicle) Proxy() string {
	return ""
}

func (f *FileVehicle) Write(buf []byte) error {
	return safeWrite(f.path, buf)
}

func NewFileVehicle(path string) *FileVehicle {
	return &FileVehicle{path: path}
}

type HTTPVehicle struct {
	url       string
	path      string
	proxy     string
	header    http.Header
	timeout   time.Duration
	sizeLimit int64
	inRead    func(response *http.Response)
	provider  P.ProxyProvider

	// fallbackURLs are tried in order after url, each with a timeout of
	// its own; name is the provider they belong to, for the log.
	fallbackURLs []string
	name         string
	lastURL      atomic.Value // string, the address that answered last
}

// HTTPVehicleOption sets what a vehicle has beyond its address.
type HTTPVehicleOption func(h *HTTPVehicle)

// WithFallbackURLs gives the vehicle addresses to try in order when the
// main one does not answer. The provider name goes to the log.
func WithFallbackURLs(provider string, urls []string) HTTPVehicleOption {
	return func(h *HTTPVehicle) {
		h.name = provider
		h.fallbackURLs = urls
	}
}

// ParseFallbackURLs checks the fallback-urls of a provider: http and
// https only, with empty entries skipped and repeats of the main url and
// of each other dropped.
func ParseFallbackURLs(main string, urls []string) ([]string, error) {
	var out []string
	seen := map[string]bool{main: true}
	for i, raw := range urls {
		raw = strings.TrimSpace(raw)
		if raw == "" || seen[raw] {
			continue
		}
		u, err := URL.Parse(raw)
		if err != nil {
			return nil, fmt.Errorf("fallback-urls: entry %d is not a valid address", i+1)
		}
		if scheme := strings.ToLower(u.Scheme); scheme != "http" && scheme != "https" || u.Host == "" {
			return nil, fmt.Errorf("fallback-urls: %s is not an http or https address", logURL(raw))
		}
		seen[raw] = true
		out = append(out, raw)
	}
	return out, nil
}

// logURL is an address fit for the log: no user info and no query, where
// subscription tokens live.
func logURL(raw string) string {
	u, err := URL.Parse(raw)
	if err != nil {
		return "<invalid url>"
	}
	u.User = nil
	u.RawQuery = ""
	u.ForceQuery = false
	u.Fragment = ""
	u.RawFragment = ""
	return u.String()
}

// reason is the error of an attempt without the address, which a request
// error repeats with its query.
func reason(err error) error {
	var urlErr *URL.Error
	if errors.As(err, &urlErr) {
		return urlErr.Err
	}
	return err
}

func (h *HTTPVehicle) Url() string {
	return h.url
}

// LastURL is the address that answered the last read, when the vehicle has
// fallback addresses; otherwise it is empty.
func (h *HTTPVehicle) LastURL() string {
	if s, ok := h.lastURL.Load().(string); ok {
		return s
	}
	return ""
}

// LastURL is the address an http vehicle with fallback addresses read
// last, without its query, for the API; empty for every other vehicle.
func LastURL(vehicle P.Vehicle) string {
	if h, ok := vehicle.(*HTTPVehicle); ok {
		if last := h.LastURL(); last != "" {
			return logURL(last)
		}
	}
	return ""
}

func (h *HTTPVehicle) Type() P.VehicleType {
	return P.HTTP
}

func (h *HTTPVehicle) Path() string {
	return h.path
}

func (h *HTTPVehicle) Proxy() string {
	return h.proxy
}

func (h *HTTPVehicle) Write(buf []byte) error {
	return safeWrite(h.path, buf)
}

func (h *HTTPVehicle) SetInRead(fn func(response *http.Response)) {
	h.inRead = fn
}

func (h *HTTPVehicle) Read(ctx context.Context, oldHash utils.HashType) (buf []byte, hash utils.HashType, err error) {
	if len(h.fallbackURLs) == 0 {
		return h.readURL(ctx, h.url, oldHash, false)
	}
	urls := append([]string{h.url}, h.fallbackURLs...)
	reasons := make([]string, 0, len(urls))
	for i, url := range urls {
		buf, hash, err = h.readURL(ctx, url, oldHash, true)
		if err == nil {
			h.lastURL.Store(url)
			return
		}
		reasons = append(reasons, fmt.Sprintf("%s: %s", logURL(url), reason(err)))
		if ctx.Err() != nil {
			break
		}
		if i+1 < len(urls) {
			log.Warnln("[Provider] %s: %s did not answer (%s), trying %s", h.name, logURL(url), reason(err), logURL(urls[i+1]))
		}
	}
	return nil, utils.HashType{}, fmt.Errorf("no address answered: %s", strings.Join(reasons, "; "))
}

// readURL reads one address with a timeout of its own. With fallback
// addresses, inRead sees only the response that answered; a lone address
// keeps showing it every response, as before.
func (h *HTTPVehicle) readURL(ctx context.Context, url string, oldHash utils.HashType, fallback bool) (buf []byte, hash utils.HashType, err error) {
	ctx, cancel := context.WithTimeout(ctx, h.timeout)
	defer cancel()
	header := h.header
	setIfNoneMatch := false
	if etag && oldHash.IsValid() {
		etagWithHash := cachefile.Cache().GetETagWithHash(url)
		if oldHash.Equal(etagWithHash.Hash) && etagWithHash.ETag != "" {
			if header == nil {
				header = http.Header{}
			} else {
				header = header.Clone()
			}
			header.Set("If-None-Match", etagWithHash.ETag)
			setIfNoneMatch = true
		}
	}
	resp, err := mihomoHttp.HttpRequest(ctx, url, http.MethodGet, header, nil, mihomoHttp.WithSpecialProxy(h.proxy))
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if h.inRead != nil && !fallback {
		h.inRead(resp)
	}

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		if setIfNoneMatch && resp.StatusCode == http.StatusNotModified {
			if h.inRead != nil && fallback {
				h.inRead(resp)
			}
			return nil, oldHash, nil
		}
		err = errors.New(resp.Status)
		return
	}
	var reader io.Reader = resp.Body
	if h.sizeLimit > 0 {
		reader = io.LimitReader(reader, h.sizeLimit)
	}
	buf, err = io.ReadAll(reader)
	if err != nil {
		return
	}
	if h.inRead != nil && fallback {
		h.inRead(resp)
	}
	hash = utils.MakeHash(buf)
	if etag {
		cachefile.Cache().SetETagWithHash(url, cachefile.EtagWithHash{
			Hash: hash,
			ETag: resp.Header.Get("ETag"),
			Time: time.Now(),
		})
	}
	return
}

func NewHTTPVehicle(url string, path string, proxy string, header http.Header, timeout time.Duration, sizeLimit int64, options ...HTTPVehicleOption) *HTTPVehicle {
	h := &HTTPVehicle{
		url:       url,
		path:      path,
		proxy:     proxy,
		header:    header,
		timeout:   timeout,
		sizeLimit: sizeLimit,
	}
	for _, option := range options {
		option(h)
	}
	return h
}
