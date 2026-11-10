package xdrive

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"

	"github.com/metacubex/mihomo/transport/xhttp"
)

// Options is the mihomo YAML of the transport, the xdriveSettings of Xray-core
// in kebab-case: xdrive-opts of a vless proxy and xdrive-config of a vless
// listener. Numbers left at 0 take the defaults of Xray-core, see params.go.
type Options struct {
	Service           string         `proxy:"service,omitempty" inbound:"service,omitempty"`
	RemoteFolder      string         `proxy:"remote-folder,omitempty" inbound:"remote-folder,omitempty"`
	Secrets           []string       `proxy:"secrets,omitempty" inbound:"secrets,omitempty"`
	SegmentBytes      int            `proxy:"segment-bytes,omitempty" inbound:"segment-bytes,omitempty"`
	FlushIntervalMs   int            `proxy:"flush-interval-ms,omitempty" inbound:"flush-interval-ms,omitempty"`
	PollIntervalMs    int            `proxy:"poll-interval-ms,omitempty" inbound:"poll-interval-ms,omitempty"`
	MaxPollIntervalMs int            `proxy:"max-poll-interval-ms,omitempty" inbound:"max-poll-interval-ms,omitempty"`
	SessionTtlSeconds int            `proxy:"session-ttl-seconds,omitempty" inbound:"session-ttl-seconds,omitempty"`
	Concurrency       int            `proxy:"concurrency,omitempty" inbound:"concurrency,omitempty"`
	EagerWindowMs     int            `proxy:"eager-window-ms,omitempty" inbound:"eager-window-ms,omitempty"`
	HoleTimeoutMs     int            `proxy:"hole-timeout-ms,omitempty" inbound:"hole-timeout-ms,omitempty"`
	Template          any            `proxy:"template,omitempty" inbound:"template,omitempty"`
	S3                *S3Options     `proxy:"s3,omitempty" inbound:"s3,omitempty"`
	ReuseSettings     *ReuseSettings `proxy:"reuse-settings,omitempty" inbound:"reuse-settings,omitempty"`
	// Address and Port are streamSettings.address and port of Xray-core: where
	// to connect instead of the host and port of the service's URL.
	Address string `proxy:"address,omitempty" inbound:"address,omitempty"`
	Port    int    `proxy:"port,omitempty" inbound:"port,omitempty"`
}

// S3Options is the s3 block of Options.
type S3Options struct {
	Endpoint  string `proxy:"endpoint,omitempty" inbound:"endpoint,omitempty"`
	Region    string `proxy:"region,omitempty" inbound:"region,omitempty"`
	Bucket    string `proxy:"bucket,omitempty" inbound:"bucket,omitempty"`
	PathStyle *bool  `proxy:"path-style,omitempty" inbound:"path-style,omitempty"`
}

// ReuseSettings is the XMUX of Options, the same fields as the reuse-settings
// of xhttp-opts.
type ReuseSettings struct {
	MaxConcurrency   string `proxy:"max-concurrency,omitempty" inbound:"max-concurrency,omitempty"`
	MaxConnections   string `proxy:"max-connections,omitempty" inbound:"max-connections,omitempty"`
	CMaxReuseTimes   string `proxy:"c-max-reuse-times,omitempty" inbound:"c-max-reuse-times,omitempty"`
	HMaxRequestTimes string `proxy:"h-max-request-times,omitempty" inbound:"h-max-request-times,omitempty"`
	HMaxReusableSecs string `proxy:"h-max-reusable-secs,omitempty" inbound:"h-max-reusable-secs,omitempty"`
	HKeepAlivePeriod int    `proxy:"h-keep-alive-period,omitempty" inbound:"h-keep-alive-period,omitempty"`
}

// Build turns Options into a normalized Config. h3 says whether the service
// is reached over HTTP/3 alone (alpn is exactly h3).
func (o Options) Build(h3 bool) (*Config, error) {
	if o.Service == "" {
		return nil, errors.New("xdrive: service is required (google-drive, template, s3 or local)")
	}
	// Xray-core reads these numbers as uint32 and rejects anything else; a
	// negative one would wrap around to a huge count or interval here.
	for _, field := range []struct {
		name  string
		value int
	}{
		{"segment-bytes", o.SegmentBytes},
		{"flush-interval-ms", o.FlushIntervalMs},
		{"poll-interval-ms", o.PollIntervalMs},
		{"max-poll-interval-ms", o.MaxPollIntervalMs},
		{"session-ttl-seconds", o.SessionTtlSeconds},
		{"concurrency", o.Concurrency},
		{"eager-window-ms", o.EagerWindowMs},
		{"hole-timeout-ms", o.HoleTimeoutMs},
	} {
		if field.value < 0 || uint64(field.value) > math.MaxUint32 {
			return nil, fmt.Errorf("xdrive: %s must be from 0 to %d, not %d", field.name, uint32(math.MaxUint32), field.value)
		}
	}
	config := &Config{
		RemoteFolder:      o.RemoteFolder,
		Service:           o.Service,
		Secrets:           o.Secrets,
		SegmentBytes:      uint32(o.SegmentBytes),
		FlushIntervalMs:   uint32(o.FlushIntervalMs),
		PollIntervalMs:    uint32(o.PollIntervalMs),
		MaxPollIntervalMs: uint32(o.MaxPollIntervalMs),
		SessionTtlSeconds: uint32(o.SessionTtlSeconds),
		Concurrency:       uint32(o.Concurrency),
		EagerWindowMs:     uint32(o.EagerWindowMs),
		HoleTimeoutMs:     uint32(o.HoleTimeoutMs),
	}
	if o.Service == "template" {
		template, err := templateJSON(o.Template)
		if err != nil {
			return nil, err
		}
		config.Template = template
	}
	if o.S3 != nil {
		config.S3 = &S3Config{
			Endpoint:  o.S3.Endpoint,
			Region:    o.S3.Region,
			Bucket:    o.S3.Bucket,
			PathStyle: o.S3.PathStyle == nil || *o.S3.PathStyle,
		}
	}
	if o.ReuseSettings != nil {
		reuse := o.ReuseSettings
		config.Xmux = &XmuxConfig{HKeepAlivePeriod: int64(reuse.HKeepAlivePeriod)}
		for _, field := range []struct {
			name   string
			value  string
			target **Range
		}{
			{"max-concurrency", reuse.MaxConcurrency, &config.Xmux.MaxConcurrency},
			{"max-connections", reuse.MaxConnections, &config.Xmux.MaxConnections},
			{"c-max-reuse-times", reuse.CMaxReuseTimes, &config.Xmux.CMaxReuseTimes},
			{"h-max-request-times", reuse.HMaxRequestTimes, &config.Xmux.HMaxRequestTimes},
			{"h-max-reusable-secs", reuse.HMaxReusableSecs, &config.Xmux.HMaxReusableSecs},
		} {
			if field.value == "" {
				continue
			}
			parsed, err := xhttp.ParseRange(field.value, "0")
			if err != nil {
				return nil, fmt.Errorf("xdrive: invalid reuse-settings %s: %w", field.name, err)
			}
			if !fitsInt32(parsed.Min) || !fitsInt32(parsed.Max) {
				return nil, fmt.Errorf("xdrive: reuse-settings %s is out of range: %s", field.name, field.value)
			}
			*field.target = &Range{From: int32(parsed.Min), To: int32(parsed.Max)}
		}
	}
	if err := config.Normalize(h3); err != nil {
		return nil, err
	}
	return config, nil
}

// fitsInt32 says whether a number of reuse-settings fits the int32 range of
// Xray-core's RangeConfig.
func fitsInt32(v int) bool {
	return int64(v) >= math.MinInt32 && int64(v) <= math.MaxInt32
}

// templateKeys maps the kebab-case keys of a template to the JSON that the
// storage is described in, for the keys that have one. The maps inside a
// template, headers and form, have keys of the user's and stay as they are.
var templateKeys = map[string]string{
	"token-url":   "tokenUrl",
	"token-path":  "tokenPath",
	"expiry-path": "expiryPath",
	"names-regex": "namesRegex",
	"href-path":   "hrefPath",
	"href-method": "hrefMethod",
	"rate-reason": "rateReason",
}

var templateOpaque = map[string]bool{"header": true, "headers": true, "form": true}

// templateJSON renders a template given as a YAML mapping with kebab-case or
// Xray camelCase keys, or as a string holding the JSON of Xray-core.
func templateJSON(value any) (string, error) {
	switch template := value.(type) {
	case nil:
		return "", errors.New(`xdrive: service "template" needs a template`)
	case string:
		if !json.Valid([]byte(template)) {
			return "", errors.New("xdrive: the template string is not valid JSON")
		}
		return template, nil
	case map[string]any:
		encoded, err := json.Marshal(templateKeysToJSON(template))
		if err != nil {
			return "", fmt.Errorf("xdrive: bad template: %w", err)
		}
		return string(encoded), nil
	default:
		return "", fmt.Errorf("xdrive: the template must be a mapping or a JSON string, not %T", value)
	}
}

func templateKeysToJSON(in map[string]any) map[string]any {
	out := make(map[string]any, len(in))
	for key, value := range in {
		if renamed, ok := templateKeys[key]; ok {
			key = renamed
		}
		if nested, ok := value.(map[string]any); ok && !templateOpaque[key] {
			value = templateKeysToJSON(nested)
		}
		out[key] = value
	}
	return out
}

// TemplateKeysFromJSON renames the structural keys of a template in Xray-core's
// JSON to kebab-case, for a subscription converter that writes mihomo YAML.
func TemplateKeysFromJSON(in map[string]any) map[string]any {
	out := make(map[string]any, len(in))
	for key, value := range in {
		for kebab, camel := range templateKeys {
			if key == camel {
				key = kebab
				break
			}
		}
		if nested, ok := value.(map[string]any); ok && !templateOpaque[key] {
			value = TemplateKeysFromJSON(nested)
		}
		out[key] = value
	}
	return out
}
