package xdrive

import (
	"context"
	"encoding/json"
	"errors"
	"net"

	"github.com/metacubex/quic-go"
)

// Config is what Xray-core calls xdriveSettings. A zero numeric field takes
// the default of Xray-core, see Params.
type Config struct {
	RemoteFolder      string
	Service           string
	Secrets           []string
	SegmentBytes      uint32
	FlushIntervalMs   uint32
	PollIntervalMs    uint32
	MaxPollIntervalMs uint32
	SessionTtlSeconds uint32
	Concurrency       uint32
	EagerWindowMs     uint32
	HoleTimeoutMs     uint32
	// Template is the JSON of the "template" service.
	Template string
	// Xmux, when nil or empty, is filled by Normalize.
	Xmux *XmuxConfig
	S3   *S3Config
}

// S3Config is the "s3" object of the service of the same name. PathStyle
// defaults to true in Xray-core when it is absent: Normalize leaves it to the
// caller, see Options in adapter/outbound.
type S3Config struct {
	Endpoint  string
	Region    string
	Bucket    string
	PathStyle bool
}

// Range is the from-to of an XMUX field, the same as in xhttp.
type Range struct {
	From, To int32
}

// XmuxConfig is the XMUX of the connections to the storage service.
type XmuxConfig struct {
	MaxConcurrency   *Range
	MaxConnections   *Range
	CMaxReuseTimes   *Range
	HMaxRequestTimes *Range
	HMaxReusableSecs *Range
	HKeepAlivePeriod int64
}

func (c *XmuxConfig) empty() bool {
	return c == nil || *c == XmuxConfig{}
}

// Normalize validates c as Xray-core's XDriveConfig.Build does and fills what
// it fills. h3 says whether the service is reached over HTTP/3 alone.
func (c *Config) Normalize(h3 bool) error {
	switch c.Service {
	case "local":
	case "Google Drive":
		c.Service = "google-drive"
		fallthrough
	case "google-drive":
		if len(c.Secrets) != 3 {
			return errors.New("xdrive: Google Drive needs 3 secrets in order of ClientID, ClientSecret, RefreshToken")
		}
	case "template":
		if c.Template == "" {
			return errors.New(`xdrive: service "template" needs a template`)
		}
		if !json.Valid([]byte(c.Template)) {
			return errors.New("xdrive: the template is not valid JSON")
		}
	case "s3":
		if c.S3 == nil {
			return errors.New(`xdrive: service "s3" needs an s3 object`)
		}
		if err := ValidateS3Config(c); err != nil {
			return err
		}
	default:
		return errors.New(`xdrive: unknown service "` + c.Service + `", use "google-drive", "template", "s3" or "local"`)
	}
	if c.Xmux == nil {
		c.Xmux = &XmuxConfig{}
	}
	if isSetRange(c.Xmux.MaxConnections) && isSetRange(c.Xmux.MaxConcurrency) {
		return errors.New("xdrive: max-connections cannot be specified together with max-concurrency")
	}
	if c.Xmux.empty() {
		c.Xmux.MaxConnections = &Range{From: 1, To: 1}
		if c.Service == "google-drive" && !h3 {
			// Google gives an h2 connection 1 MiB of window, which a few sessions on
			// a long rtt would share, an h3 connection has no such limit
			c.Xmux.MaxConnections = &Range{From: 4, To: 4}
		}
		c.Xmux.HMaxReusableSecs = &Range{From: 1800, To: 3000}
	}
	return nil
}

func isSetRange(r *Range) bool {
	return r != nil && r.To > 0
}

// Dialer opens the connections to the storage service for the proxy or the
// listener that uses the transport, with its dialer-proxy, interface, marks
// and finalmask. A nil Dialer dials directly.
type Dialer struct {
	// Address and Port, when set, replace the host and the port that a URL
	// names as where to connect, as streamSettings.address and port do in
	// Xray-core; the URL's host stays the Host and the default SNI.
	Address string
	Port    int
	// DialTCP dials addr. Nil means the system dialer.
	DialTCP func(ctx context.Context, addr string) (net.Conn, error)
	// WrapTLS runs the client handshake over raw, for host, with host as SNI
	// unless a server name is configured. Nil means Go TLS verifying host.
	WrapTLS func(ctx context.Context, raw net.Conn, host string) (net.Conn, error)
	// H3, when true, reaches the service over HTTP/3 alone.
	H3 bool
	// DialQUIC opens the QUIC connection of H3 to addr, for host.
	DialQUIC func(ctx context.Context, addr, host string, cfg *quic.Config) (*quic.Conn, error)
}
