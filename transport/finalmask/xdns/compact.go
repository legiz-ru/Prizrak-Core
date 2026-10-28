package xdns

import (
	"errors"
	"fmt"
	"strings"
)

// compactEDNS0 is the EDNS0 payload the first xdns client advertised on
// every query. A compact entry has no field for it, so it keeps that size.
const compactEDNS0 = 4096

// ExpandCompact rewrites the compact spellings of the first Xray-core xdns
// (before its "Refactor and new parameters" change, which this package
// follows) into the structured settings: a `resolvers` entry
// "<domain>[:<method>]+udp://<server>" names the zone, the record type and
// one resolver; a `domains` entry "<domain>[:<method>]" names a zone. The
// method is txt (the default of a resolver entry), a or aaaa; a domain
// entry without a method keeps every type. Structured entries stay as they
// are, so the two spellings may be mixed.
func ExpandCompact(settings map[string]any) error {
	domains, _ := settings["domains"].([]any)
	resolvers, _ := settings["resolvers"].([]any)
	zones := compactZones{}
	outDomains := make([]any, 0, len(domains))
	for _, entry := range domains {
		spec, ok := entry.(string)
		if !ok {
			outDomains = append(outDomains, entry)
			continue
		}
		name, rrType, err := parseCompactDomain(spec, "")
		if err != nil {
			return fmt.Errorf("xdns: domain %q: %w", spec, err)
		}
		zones.add(name, rrType)
	}
	outResolvers := make([]any, 0, len(resolvers))
	for _, entry := range resolvers {
		spec, ok := entry.(string)
		if !ok {
			outResolvers = append(outResolvers, entry)
			continue
		}
		name, rrType, server, err := parseCompactResolver(spec)
		if err != nil {
			return fmt.Errorf("xdns: resolver %q: %w", spec, err)
		}
		zones.add(name, rrType)
		outResolvers = append(outResolvers, map[string]any{"addrs": []any{server}})
	}
	if len(zones.order) == 0 && len(outDomains) == len(domains) && len(outResolvers) == len(resolvers) {
		return nil
	}
	settings["domains"] = append(outDomains, zones.entries()...)
	settings["resolvers"] = outResolvers
	return nil
}

// compactZones collects the zones the compact entries name, one entry per
// distinct name and record type, in the order they first appeared.
type compactZones struct {
	order []string
	seen  map[string]map[string]any
}

func (z *compactZones) add(name string, rrType uint16) {
	key := fmt.Sprintf("%s/%d", name, rrType)
	if z.seen == nil {
		z.seen = map[string]map[string]any{}
	}
	if _, ok := z.seen[key]; ok {
		return
	}
	entry := map[string]any{"names": []any{name}, "edns0": int64(compactEDNS0)}
	if rrType != 0 {
		entry["types"] = []any{int64(rrType)}
	}
	z.seen[key] = entry
	z.order = append(z.order, key)
}

func (z *compactZones) entries() []any {
	out := make([]any, 0, len(z.order))
	for _, key := range z.order {
		out = append(out, z.seen[key])
	}
	return out
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
