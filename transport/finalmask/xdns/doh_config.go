package xdns

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"runtime"
	"strconv"
	"strings"
	"time"

	tlsC "github.com/metacubex/mihomo/component/tls"
	"github.com/metacubex/mihomo/log"
)

// The tls-config and quic-config of an https resolver: Xray's tlsConfig and
// quicConfig with the keys in kebab-case (serverName to server-name), as the
// finalmask block writes every Xray key.

// stringList reads Xray's StringList: a list, or one string with the values
// comma-separated.
type stringList []string

func (l *stringList) UnmarshalText(text []byte) error {
	*l = nil
	for _, v := range strings.Split(string(text), ",") {
		if v = strings.TrimSpace(v); v != "" {
			*l = append(*l, v)
		}
	}
	return nil
}

// values splits entries that hold several comma-separated values, as a list
// written in YAML may.
func (l stringList) values() []string {
	var out []string
	for _, entry := range l {
		for _, v := range strings.Split(entry, ",") {
			if v = strings.TrimSpace(v); v != "" {
				out = append(out, v)
			}
		}
	}
	return out
}

// TLSOption is the tls-config of an https resolver.
type TLSOption struct {
	// ServerName is the SNI, the host of the URL by default. Set apart from
	// that host, it fronts the request: the TLS goes to this name while the
	// HTTP request still names the URL's host.
	ServerName string `proxy:"server-name,omitempty"`
	// ALPN is h2 and http/1.1 by default; exactly h3 sends the queries over
	// HTTP/3.
	ALPN stringList `proxy:"alpn,omitempty"`
	// Fingerprint is the Client Hello: chrome by default, as in Xray,
	// another uTLS one by the names client-fingerprint takes, or unsafe for
	// Go's own TLS. Over HTTP/3 it picks the browser of the QUIC handshake
	// as a proxy's client-fingerprint does (common.QUICParrot): Firefox's
	// names are Firefox, any other value, unsafe too, is Chrome; quic-config's
	// disable-chrome-parrot sends quic-go's own handshake.
	Fingerprint string `proxy:"fingerprint,omitempty"`
	// PinnedPeerCertSha256 are hex SHA-256 sums of a certificate of the
	// chain: the leaf passes as it is, a CA verifies the leaf.
	PinnedPeerCertSha256 stringList `proxy:"pinned-peer-cert-sha256,omitempty"`
	// VerifyPeerCertByName are names the certificate is checked against
	// instead of the server name.
	VerifyPeerCertByName stringList `proxy:"verify-peer-cert-by-name,omitempty"`
	// ECHConfigList is an ECHConfigList in base64.
	ECHConfigList string `proxy:"ech-config-list,omitempty"`
	// AllowInsecure is refused, as Xray refuses it.
	AllowInsecure bool `proxy:"allow-insecure,omitempty"`
}

// TLSConfig is the built tls-config.
type TLSConfig struct {
	ServerName  string
	NextProtos  []string
	Fingerprint string // "" for Go's TLS
	Pins        [][]byte
	VerifyNames []string
	ECH         []byte
}

// H3 reports whether the resolver speaks HTTP/3.
func (c *TLSConfig) H3() bool {
	return c != nil && len(c.NextProtos) == 1 && c.NextProtos[0] == "h3"
}

func (o *TLSOption) Build() (*TLSConfig, error) {
	if o.AllowInsecure {
		return nil, errors.New("xdns: allow-insecure of tls-config is removed in Xray-core, use pinned-peer-cert-sha256 or verify-peer-cert-by-name")
	}
	c := &TLSConfig{
		ServerName:  strings.TrimSpace(o.ServerName),
		NextProtos:  o.ALPN.values(),
		VerifyNames: o.VerifyPeerCertByName.values(),
	}
	fingerprint := strings.ToLower(strings.TrimSpace(o.Fingerprint))
	switch fingerprint {
	case "":
		c.Fingerprint = "chrome"
	case "unsafe":
	default:
		if _, ok := tlsC.GetFingerprint(fingerprint); !ok {
			return nil, fmt.Errorf("xdns: unknown fingerprint %q in tls-config", o.Fingerprint)
		}
		c.Fingerprint = fingerprint
	}
	for _, pin := range o.PinnedPeerCertSha256.values() {
		sum, err := hex.DecodeString(strings.ReplaceAll(pin, ":", ""))
		if err != nil || len(sum) != sha256.Size {
			return nil, fmt.Errorf("xdns: pinned-peer-cert-sha256 %q is not a hex SHA-256", pin)
		}
		c.Pins = append(c.Pins, sum)
	}
	if list := strings.TrimSpace(o.ECHConfigList); list != "" {
		raw, err := base64.StdEncoding.DecodeString(list)
		if err != nil {
			return nil, fmt.Errorf("xdns: ech-config-list of tls-config takes an ECHConfigList in base64: %w", err)
		}
		c.ECH = raw
	}
	return c, nil
}

// verifyPeer is Xray's check of a pinned certificate and of the names to
// verify by: a pinned leaf passes, a pinned CA becomes the only root.
func (c *TLSConfig) verifyPeer(rawCerts [][]byte, roots *x509.CertPool, serverName string, now time.Time) error {
	certs := make([]*x509.Certificate, 0, len(rawCerts))
	for _, raw := range rawCerts {
		cert, err := x509.ParseCertificate(raw)
		if err != nil {
			return err
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return errors.New("xdns: the resolver sent no certificate")
	}
	pinnedCA := false
	if len(c.Pins) > 0 {
		found := -1
		for i, cert := range certs {
			if i > 0 && !cert.IsCA {
				// As Xray: a pin below the leaf names a CA.
				continue
			}
			sum := sha256.Sum256(cert.Raw)
			for _, pin := range c.Pins {
				if bytes.Equal(sum[:], pin) {
					found = i
					break
				}
			}
			if found >= 0 {
				break
			}
		}
		switch {
		case found < 0:
			return errors.New("xdns: the resolver's certificate is not pinned by pinned-peer-cert-sha256")
		case found == 0:
			return nil
		}
		roots = x509.NewCertPool()
		roots.AddCert(certs[found])
		pinnedCA = true
	}
	opts := x509.VerifyOptions{Roots: roots, CurrentTime: now, Intermediates: x509.NewCertPool()}
	for _, cert := range certs[1:] {
		opts.Intermediates.AddCert(cert)
	}
	if len(c.VerifyNames) > 0 {
		for _, opts.DNSName = range c.VerifyNames {
			if _, err := certs[0].Verify(opts); err == nil {
				return nil
			}
		}
		return errors.New("xdns: the resolver's certificate is not valid for verify-peer-cert-by-name")
	}
	if pinnedCA {
		opts.DNSName = serverName
		if _, err := certs[0].Verify(opts); err != nil {
			return fmt.Errorf("xdns: the resolver's certificate is not valid against the pinned CA: %w", err)
		}
	}
	return nil
}

// QUICOption is the quic-config of an https resolver over HTTP/3.
type QUICOption struct {
	// Congestion is reno (quic-go's own, the default), bbr or force-brutal.
	Congestion string `proxy:"congestion,omitempty"`
	// BBRProfile is conservative, standard (the default) or aggressive.
	BBRProfile string `proxy:"bbr-profile,omitempty"`
	// BrutalUp is the rate of force-brutal, as Xray writes a bandwidth: "50
	// mbps", with k, m, g and t in steps of 1000.
	BrutalUp                      string `proxy:"brutal-up,omitempty"`
	BrutalDown                    string `proxy:"brutal-down,omitempty"`
	BrutalDisableLossCompensation bool   `proxy:"brutal-disable-loss-compensation,omitempty"`
	InitStreamReceiveWindow       uint64 `proxy:"init-stream-receive-window,omitempty"`
	MaxStreamReceiveWindow        uint64 `proxy:"max-stream-receive-window,omitempty"`
	InitConnectionReceiveWindow   uint64 `proxy:"init-connection-receive-window,omitempty"`
	MaxConnectionReceiveWindow    uint64 `proxy:"max-connection-receive-window,omitempty"`
	// MaxIdleTimeout and KeepAlivePeriod are in seconds.
	MaxIdleTimeout          int64 `proxy:"max-idle-timeout,omitempty"`
	KeepAlivePeriod         int64 `proxy:"keep-alive-period,omitempty"`
	DisablePathMTUDiscovery bool  `proxy:"disable-path-mtu-discovery,omitempty"`
	// DisableChromeParrot sends quic-go's own QUIC handshake instead of the
	// browser's of tls-config's fingerprint, as Xray's disableChromeParrot.
	DisableChromeParrot bool `proxy:"disable-chrome-parrot,omitempty"`
	// DisableGSO is read for Xray configs; GSO is left to quic-go.
	DisableGSO bool `proxy:"disable-gso,omitempty"`
}

// QUICConfig is the built quic-config.
type QUICConfig struct {
	Congestion                     string
	BBRProfile                     string
	BrutalUp                       uint64 // bytes per second
	InitialStreamReceiveWindow     uint64
	MaxStreamReceiveWindow         uint64
	InitialConnectionReceiveWindow uint64
	MaxConnectionReceiveWindow     uint64
	MaxIdleTimeout                 time.Duration
	KeepAlivePeriod                time.Duration
	DisablePathMTUDiscovery        bool
	DisableChromeParrot            bool
}

// Build checks the settings as Xray's QuicParamsConfig does; the
// congestion control is checked for DoH by checkHTTPS.
func (o *QUICOption) Build() (*QUICConfig, error) {
	profile := strings.ToLower(strings.TrimSpace(o.BBRProfile))
	switch profile {
	case "":
		profile = "standard"
	case "conservative", "standard", "aggressive":
	default:
		return nil, fmt.Errorf("xdns: unknown bbr-profile %q, want conservative, standard or aggressive", o.BBRProfile)
	}
	up, err := ParseBandwidth(o.BrutalUp)
	if err != nil {
		return nil, fmt.Errorf("xdns: brutal-up: %w", err)
	}
	down, err := ParseBandwidth(o.BrutalDown)
	if err != nil {
		return nil, fmt.Errorf("xdns: brutal-down: %w", err)
	}
	if up > 0 && up < 65536 {
		return nil, errors.New("xdns: brutal-up must be at least 65536 bytes per second")
	}
	if down > 0 && down < 65536 {
		return nil, errors.New("xdns: brutal-down must be at least 65536 bytes per second")
	}
	congestion := strings.ToLower(strings.TrimSpace(o.Congestion))
	switch congestion {
	case "", "brutal", "reno", "bbr":
	case "force-brutal":
		if up == 0 {
			return nil, errors.New("xdns: congestion force-brutal needs brutal-up")
		}
	default:
		return nil, fmt.Errorf("xdns: unknown congestion %q, want reno, bbr, brutal or force-brutal", o.Congestion)
	}
	for _, w := range []struct {
		name  string
		value uint64
	}{
		{"init-stream-receive-window", o.InitStreamReceiveWindow},
		{"max-stream-receive-window", o.MaxStreamReceiveWindow},
		{"init-connection-receive-window", o.InitConnectionReceiveWindow},
		{"max-connection-receive-window", o.MaxConnectionReceiveWindow},
	} {
		if w.value > 0 && w.value < 16384 {
			return nil, fmt.Errorf("xdns: %s must be at least 16384", w.name)
		}
	}
	if o.MaxIdleTimeout != 0 && (o.MaxIdleTimeout < 4 || o.MaxIdleTimeout > 120) {
		return nil, errors.New("xdns: max-idle-timeout must be between 4 and 120")
	}
	if o.KeepAlivePeriod != 0 && (o.KeepAlivePeriod < 2 || o.KeepAlivePeriod > 60) {
		return nil, errors.New("xdns: keep-alive-period must be between 2 and 60")
	}
	if o.BrutalDisableLossCompensation {
		// The Brutal of sing-quic always compensates for loss.
		log.Warnln("[finalmask] xdns: brutal-disable-loss-compensation is not supported, loss stays compensated")
	}
	return &QUICConfig{
		Congestion:                     congestion,
		BBRProfile:                     profile,
		BrutalUp:                       up,
		InitialStreamReceiveWindow:     o.InitStreamReceiveWindow,
		MaxStreamReceiveWindow:         o.MaxStreamReceiveWindow,
		InitialConnectionReceiveWindow: o.InitConnectionReceiveWindow,
		MaxConnectionReceiveWindow:     o.MaxConnectionReceiveWindow,
		MaxIdleTimeout:                 time.Duration(o.MaxIdleTimeout) * time.Second,
		KeepAlivePeriod:                time.Duration(o.KeepAlivePeriod) * time.Second,
		// As Xray: path MTU discovery only where quic-go does it well.
		DisablePathMTUDiscovery: o.DisablePathMTUDiscovery || (runtime.GOOS != "linux" && runtime.GOOS != "windows" && runtime.GOOS != "darwin"),
		DisableChromeParrot:     o.DisableChromeParrot,
	}, nil
}

// checkHTTPS refuses what Xray's DoH resolver cannot run: over HTTP/3 the
// congestion control is reno, bbr or force-brutal (Xray panics on brutal).
func (r *ResolverConfig) checkHTTPS() error {
	if !r.TLS.H3() || r.QUIC == nil {
		return nil
	}
	switch r.QUIC.Congestion {
	case "", "reno", "bbr", "force-brutal":
		return nil
	default:
		return fmt.Errorf("xdns: congestion %q of an https resolver over h3, want reno, bbr or force-brutal", r.QUIC.Congestion)
	}
}

// ParseBandwidth reads an Xray Bandwidth, a rate in bits per second with an
// optional unit (b/bps, k/kb/kbps, m/mb/mbps, g/gb/gbps, t/tb/tbps) in
// steps of 1000 as in Xray-core since f0820585, and returns bytes per
// second; "" is 0.
func ParseBandwidth(s string) (uint64, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" {
		return 0, nil
	}
	i := len(s)
	for j, c := range s {
		if (c < '0' || c > '9') && c != '.' {
			i = j
			break
		}
	}
	n, err := strconv.ParseFloat(s[:i], 64)
	if err != nil {
		return 0, fmt.Errorf("invalid bandwidth %q", s)
	}
	var mul float64
	switch strings.TrimSpace(s[i:]) {
	case "", "b", "bps":
		mul = 1
	case "k", "kb", "kbps":
		mul = 1e3
	case "m", "mb", "mbps":
		mul = 1e6
	case "g", "gb", "gbps":
		mul = 1e9
	case "t", "tb", "tbps":
		mul = 1e12
	default:
		return 0, fmt.Errorf("unsupported bandwidth unit %q", strings.TrimSpace(s[i:]))
	}
	return uint64(n*mul) / 8, nil
}
