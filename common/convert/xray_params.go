package convert

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/metacubex/mihomo/log"
)

// The parameters beyond the share-link standard that the Remnawave backend
// and the Xray-core fork put into links: fm (the finalmask block as JSON),
// pqv and vcn, and the ?serverDescription= tail Happ gets after the remark.

const serverDescriptionTail = "?serverDescription="

// splitServerDescription takes the Happ server description off a link's
// fragment: Remnawave appends ?serverDescription=<base64> after the remark.
func splitServerDescription(fragment string) (name, description string) {
	i := strings.LastIndex(fragment, serverDescriptionTail)
	if i < 0 {
		return fragment, ""
	}
	name, raw := fragment[:i], fragment[i+len(serverDescriptionTail):]
	if raw == "" {
		return name, ""
	}
	if decoded, err := TryDecodeBase64(raw); err == nil && utf8.Valid(decoded) {
		return name, string(decoded)
	}
	return name, raw
}

// applyName sets the proxy's unique name from the link's fragment and keeps
// the server description beside it as serverDescription, the key the
// Remnawave mihomo template uses, so apps reading the YAML show it.
func applyName(proxy map[string]any, names map[string]int, fragment string) {
	name, description := splitServerDescription(fragment)
	proxy["name"] = uniqueName(names, name)
	if description != "" {
		proxy["serverDescription"] = description
	}
}

// finalMaskBlock keeps the tcp and udp chains of an Xray finalmask object,
// nil when it has none. The entries stay as Xray writes them (settings
// nested, camelCase keys): the finalmask option package reads that form.
// The udp chain is kept only where the proxy can use it, vless over xhttp
// with HTTP/3; Xray ignores it on the other transports, and so does this,
// rather than failing the proxy.
func finalMaskBlock(fm map[string]any, proxy map[string]any) map[string]any {
	block := make(map[string]any, 2)
	if list, ok := fm["tcp"].([]any); ok && len(list) > 0 {
		block["tcp"] = list
	}
	if list, ok := fm["udp"].([]any); ok && len(list) > 0 {
		if finalMaskUDPUsable(proxy) {
			block["udp"] = list
		} else {
			log.Debugln("finalmask.udp of %v dropped: it is for vless over xhttp with alpn h3 only", proxy["name"])
		}
	}
	if len(block) == 0 {
		return nil
	}
	return block
}

func finalMaskUDPUsable(proxy map[string]any) bool {
	if proxy["type"] != "vless" || proxy["network"] != "xhttp" {
		return false
	}
	alpn, _ := proxy["alpn"].([]string)
	return len(alpn) == 1 && alpn[0] == "h3"
}

// applyFinalMask carries fm=<JSON> of a vless or trojan link into the
// proxy's finalmask block.
func applyFinalMask(proxy map[string]any, query url.Values) {
	raw := query.Get("fm")
	if raw == "" {
		return
	}
	var fm map[string]any
	if err := json.Unmarshal([]byte(raw), &fm); err != nil {
		log.Warnln("finalmask of %v is not valid JSON, dropped: %s", proxy["name"], err)
		return
	}
	if block := finalMaskBlock(fm, proxy); block != nil {
		proxy["finalmask"] = block
	}
}

// applyHysteria2FinalMask maps the finalmask object of an Xray hysteria2
// outbound (the udp masks salamander and udphop, and quicParams) to the
// hysteria2 proxy's own fields, as the Remnawave mihomo template does.
func applyHysteria2FinalMask(proxy map[string]any, fm map[string]any) {
	if udp, ok := fm["udp"].([]any); ok {
		for _, entry := range udp {
			mask, ok := entry.(map[string]any)
			if !ok {
				continue
			}
			settings, _ := mask["settings"].(map[string]any)
			if settings == nil {
				settings = mask
			}
			typ, _ := mask["type"].(string)
			switch strings.ToLower(typ) {
			case "salamander":
				password, _ := settings["password"].(string)
				if password == "" {
					continue
				}
				proxy["obfs"] = "salamander"
				proxy["obfs-password"] = password
				// A packet size turns salamander into gecko in the fork.
				if from, to, ok := rangeBounds(settings["packetSize"]); ok && to > 0 {
					proxy["obfs"] = "gecko"
					proxy["obfs-min-packet-size"] = from
					proxy["obfs-max-packet-size"] = to
				}
			case "udphop":
				applyUDPHop(proxy, settings)
			}
		}
	}
	quic, _ := fm["quicParams"].(map[string]any)
	if quic == nil {
		return
	}
	// Remnawave's own mihomo template reads the hop settings here as well.
	if hop, ok := quic["udpHop"].(map[string]any); ok && proxy["ports"] == nil {
		applyUDPHop(proxy, hop)
	}
	if up := xrayBandwidth(quic["brutalUp"]); up != "" {
		proxy["up"] = up
	}
	if down := xrayBandwidth(quic["brutalDown"]); down != "" {
		proxy["down"] = down
	}
	if profile, _ := quic["bbrProfile"].(string); profile != "" {
		proxy["bbr-profile"] = profile
	}
	for src, dst := range map[string]string{
		"initStreamReceiveWindow":     "initial-stream-receive-window",
		"maxStreamReceiveWindow":      "max-stream-receive-window",
		"initConnectionReceiveWindow": "initial-connection-receive-window",
		"maxConnectionReceiveWindow":  "max-connection-receive-window",
	} {
		if n, ok := toUint64(quic[src]); ok && n > 0 {
			proxy[dst] = n
		}
	}
}

// applyUDPHop reads a port-hopping block in any of the fork's spellings:
// the udphop mask (remotePorts, interval), quicParams.udpHop or the old
// hysteriaSettings.udphop (ports or port, interval).
func applyUDPHop(proxy map[string]any, hop map[string]any) {
	ports := portList(hop["remotePorts"])
	if ports == "" {
		ports = portList(hop["ports"])
	}
	if ports == "" {
		ports = portList(hop["port"])
	}
	if ports != "" {
		proxy["ports"] = ports
	}
	if interval := rangeString(hop["interval"]); interval != "" {
		proxy["hop-interval"] = strings.TrimSuffix(interval, "s")
	}
}

// normalizeCertPin brings a certificate pin to the hex SHA-256 mihomo's
// fingerprint takes: hex with or without colons, or the base64 of the 32
// bytes. Anything else gives "".
func normalizeCertPin(pin string) string {
	pin = strings.TrimSpace(pin)
	if pin == "" {
		return ""
	}
	clean := strings.ToLower(strings.NewReplacer(":", "", " ", "").Replace(pin))
	if raw, err := hex.DecodeString(clean); err == nil && len(raw) == 32 {
		return clean
	}
	if raw, err := TryDecodeBase64(pin); err == nil && len(raw) == 32 {
		return hex.EncodeToString(raw)
	}
	return ""
}

// rangeString renders an Xray Int32Range (a number or "from-to") as the
// range string mihomo reads.
func rangeString(v any) string {
	switch v := v.(type) {
	case string:
		return strings.TrimSpace(v)
	case float64:
		return strconv.FormatInt(int64(v), 10)
	case int:
		return strconv.Itoa(v)
	}
	return ""
}

func rangeBounds(v any) (from, to int, ok bool) {
	s := rangeString(v)
	if s == "" {
		return 0, 0, false
	}
	first, second, found := strings.Cut(s, "-")
	from, err := strconv.Atoi(strings.TrimSpace(first))
	if err != nil {
		return 0, 0, false
	}
	if !found {
		return from, from, true
	}
	to, err = strconv.Atoi(strings.TrimSpace(second))
	if err != nil {
		return 0, 0, false
	}
	return from, to, true
}

// portList renders remotePorts, a string, a number or a list of them, as
// mihomo's ports: "443,20000-30000".
func portList(v any) string {
	switch v := v.(type) {
	case string:
		return strings.ReplaceAll(strings.TrimSpace(v), " ", "")
	case float64:
		return strconv.FormatInt(int64(v), 10)
	case []any:
		parts := make([]string, 0, len(v))
		for _, item := range v {
			if s := portList(item); s != "" {
				parts = append(parts, s)
			}
		}
		return strings.Join(parts, ",")
	}
	return ""
}

func toUint64(v any) (uint64, bool) {
	switch v := v.(type) {
	case float64:
		if v < 0 || v > math.MaxUint64 {
			return 0, false
		}
		return uint64(v), true
	case string:
		n, err := strconv.ParseUint(strings.TrimSpace(v), 10, 64)
		return n, err == nil
	}
	return 0, false
}

// xrayBandwidth renders an Xray Bandwidth (a bare number of bits per second
// or a number with a k/m/g suffix in steps of 1024) as a rate mihomo's
// StringToBps reads: "<n> Mbps" when it divides evenly, else "<n> bps". A
// bare number cannot pass as it is: mihomo takes one for megabits.
func xrayBandwidth(v any) string {
	var bits float64
	switch v := v.(type) {
	case float64:
		bits = v
	case string:
		s := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(v), " ", ""))
		if s == "" {
			return ""
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
			return ""
		}
		switch s[i:] {
		case "", "b", "bps":
		case "k", "kb", "kbps":
			n *= 1024
		case "m", "mb", "mbps":
			n *= 1024 * 1024
		case "g", "gb", "gbps":
			n *= 1024 * 1024 * 1024
		case "t", "tb", "tbps":
			n *= 1024 * 1024 * 1024 * 1024
		default:
			return ""
		}
		bits = n
	default:
		return ""
	}
	if bits <= 0 {
		return ""
	}
	whole := uint64(bits)
	if whole%1_000_000 == 0 {
		return fmt.Sprintf("%d Mbps", whole/1_000_000)
	}
	return fmt.Sprintf("%d bps", whole)
}
