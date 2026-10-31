package xdns

import (
	"errors"
	"fmt"
	"strings"
)

// ParseCompact reads the settings of the first Xray-core xdns: a `resolvers`
// entry "<domain>[:<method>]+udp://<server>" names the zone, the record
// type (txt by default, a, aaaa) and one resolver; a `domains` entry
// "<domain>[:<method>]" names a server zone. That xdns has its own framing
// on the wire (see LegacyConfig), so a config in this spelling gets the
// client of that time; ok is false when the settings are not written so.
// The two spellings are different protocols and do not mix.
func ParseCompact(settings map[string]any) (_ *LegacyConfig, ok bool, err error) {
	domains, _ := settings["domains"].([]any)
	resolvers, _ := settings["resolvers"].([]any)
	compact, structured := 0, 0
	for _, entry := range append(append([]any{}, domains...), resolvers...) {
		if _, isString := entry.(string); isString {
			compact++
		} else {
			structured++
		}
	}
	if compact == 0 {
		return nil, false, nil
	}
	if structured > 0 {
		return nil, true, errors.New("xdns: the compact spelling (\"t.example.com:aaaa+udp://1.1.1.1:53\") is the first xdns, whose wire format the structured {names}/{addrs} entries of the current xdns do not speak; write all entries one way")
	}
	for key := range settings {
		switch key {
		case "domains", "resolvers":
		default:
			return nil, true, fmt.Errorf("xdns: %s belongs to the current xdns, the compact spelling of the first one has only domains and resolvers", key)
		}
	}
	c := &LegacyConfig{}
	for _, entry := range domains {
		spec := entry.(string)
		name, _, err := parseCompactDomain(spec, "")
		if err != nil {
			return nil, true, fmt.Errorf("xdns: domain %q: %w", spec, err)
		}
		c.Domains = append(c.Domains, name)
	}
	for _, entry := range resolvers {
		spec := entry.(string)
		name, rrType, server, err := parseCompactResolver(spec)
		if err != nil {
			return nil, true, fmt.Errorf("xdns: resolver %q: %w", spec, err)
		}
		resolver, err := ParseResolver(server)
		if err != nil {
			return nil, true, err
		}
		c.Resolvers = append(c.Resolvers, LegacyResolver{Zone: name, Type: rrType, Resolver: resolver})
	}
	return c, true, nil
}

// rrTypeFromMethod reads the method of a compact entry: txt (also the
// empty method), a or aaaa.
func rrTypeFromMethod(method string) (uint16, error) {
	switch strings.ToLower(method) {
	case "", "txt":
		return TypeTXT, nil
	case "a":
		return TypeA, nil
	case "aaaa":
		return TypeAAAA, nil
	default:
		return 0, fmt.Errorf("unsupported method %q, want txt, a or aaaa", method)
	}
}

// parseCompactDomain splits "<domain>[:<method>]". With a defaultMethod the
// record type is always set (a resolver entry defaults to TXT); without one
// a bare domain keeps every type (0).
func parseCompactDomain(spec, defaultMethod string) (string, uint16, error) {
	domain, method := spec, ""
	hasMethod := false
	if i := strings.LastIndex(spec, ":"); i >= 0 {
		domain, method = spec[:i], spec[i+1:]
		hasMethod = true
	} else if defaultMethod != "" {
		method = defaultMethod
		hasMethod = true
	}
	domain = strings.TrimSuffix(strings.TrimSpace(domain), ".")
	if domain == "" {
		return "", 0, errors.New("empty domain")
	}
	if !hasMethod {
		return domain, 0, nil
	}
	rrType, err := rrTypeFromMethod(method)
	if err != nil {
		return "", 0, err
	}
	return domain, rrType, nil
}

// parseCompactResolver splits "<domain>[:<method>]+<scheme>://<server>".
// The first client knew udp only; tcp is accepted the way the structured
// `addrs` accept it.
func parseCompactResolver(spec string) (string, uint16, string, error) {
	head, server, ok := strings.Cut(spec, "+")
	if !ok {
		return "", 0, "", errors.New("invalid resolver scheme, want <domain>[:<method>]+udp://<server>")
	}
	scheme, rest, ok := strings.Cut(server, "://")
	if !ok {
		return "", 0, "", errors.New("invalid resolver scheme, want <domain>[:<method>]+udp://<server>")
	}
	switch strings.ToLower(scheme) {
	case "udp", "tcp":
	default:
		return "", 0, "", fmt.Errorf("unknown resolver scheme %q, want udp or tcp", scheme)
	}
	if rest == "" {
		return "", 0, "", errors.New("empty resolver server")
	}
	name, rrType, err := parseCompactDomain(head, "txt")
	if err != nil {
		return "", 0, "", err
	}
	return name, rrType, strings.ToLower(scheme) + "://" + rest, nil
}
