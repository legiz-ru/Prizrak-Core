package convert

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/metacubex/mihomo/log"
	Tvless "github.com/metacubex/mihomo/transport/vless"
)

// An Xray JSON subscription: an array of Xray configs, one per server, each
// with its remarks (the server's name) and its outbounds, the first of which
// is the server (the rest are freedom, blackhole, dns, or the servers an
// injector adds). Happ, Streisand, INCY, v2rayN and V2Box fetch this form;
// Remnawave serves it to them with meta.serverDescription. A single Xray
// config (an object with outbounds) converts as well, one proxy per outbound,
// named by tag.
type xrayConfig struct {
	Remarks   string         `json:"remarks"`
	Meta      xrayMeta       `json:"meta"`
	Outbounds []xrayOutbound `json:"outbounds"`
}

type xrayMeta struct {
	ServerDescription string `json:"serverDescription"`
}

type xrayOutbound struct {
	Tag            string         `json:"tag"`
	Protocol       string         `json:"protocol"`
	Settings       map[string]any `json:"settings"`
	StreamSettings map[string]any `json:"streamSettings"`
}

// IsXrayJSON reports whether the data is an Xray JSON subscription: a JSON
// array or object, possibly wrapped in base64 as some panels serve it.
func IsXrayJSON(buf []byte) bool {
	return xrayJSONBody(buf) != nil
}

// xrayJSONBody returns the JSON of an Xray subscription, unwrapping base64,
// or nil when the data is not JSON.
func xrayJSONBody(buf []byte) []byte {
	trimmed := bytes.TrimSpace(buf)
	if bytes.HasPrefix(trimmed, []byte("[")) || bytes.HasPrefix(trimmed, []byte("{")) {
		return trimmed
	}
	decoded := bytes.TrimSpace(DecodeBase64(trimmed))
	if bytes.HasPrefix(decoded, []byte("[")) || bytes.HasPrefix(decoded, []byte("{")) {
		return decoded
	}
	return nil
}

// ConvertsXrayJSON convert an Xray JSON subscription to mihomo proxies config.
func ConvertsXrayJSON(buf []byte) ([]map[string]any, error) {
	if body := xrayJSONBody(buf); body != nil {
		buf = body
	} else {
		buf = bytes.TrimSpace(buf)
	}
	var (
		configs []xrayConfig
		single  bool
	)
	switch {
	case bytes.HasPrefix(buf, []byte("[")):
		if err := json.Unmarshal(buf, &configs); err != nil {
			return nil, fmt.Errorf("convert xray json subscribe error: %w", err)
		}
	case bytes.HasPrefix(buf, []byte("{")):
		var config xrayConfig
		if err := json.Unmarshal(buf, &config); err != nil {
			return nil, fmt.Errorf("convert xray json subscribe error: %w", err)
		}
		configs = []xrayConfig{config}
		single = config.Remarks == ""
	default:
		return nil, errors.New("convert xray json subscribe error: not a JSON array or object")
	}

	proxies := make([]map[string]any, 0, len(configs))
	names := make(map[string]int, len(configs))
	for _, config := range configs {
		for _, outbound := range config.Outbounds {
			if !xrayProxyProtocol(outbound.Protocol) {
				continue
			}
			name := config.Remarks
			if single || name == "" {
				name = outbound.Tag
			}
			proxy, err := convertXrayOutbound(outbound, name, names)
			if err != nil {
				log.Warnln("xray json outbound %q skipped: %s", name, err)
				if single {
					continue
				}
				break
			}
			if config.Meta.ServerDescription != "" {
				proxy["serverDescription"] = config.Meta.ServerDescription
			}
			proxies = append(proxies, proxy)
			if !single {
				// One server per config: the other outbounds are its
				// routing, not servers of their own.
				break
			}
		}
	}

	if len(proxies) == 0 {
		return nil, errors.New("convert xray json subscribe error: no supported outbound")
	}
	return proxies, nil
}

func xrayProxyProtocol(protocol string) bool {
	switch strings.ToLower(protocol) {
	case "vless", "vmess", "trojan", "shadowsocks", "hysteria", "hysteria2":
		return true
	}
	return false
}

func convertXrayOutbound(outbound xrayOutbound, name string, names map[string]int) (map[string]any, error) {
	proxy := make(map[string]any, 24)
	proxy["name"] = uniqueName(names, name)
	proxy["udp"] = true
	stream := outbound.StreamSettings
	if stream == nil {
		stream = map[string]any{}
	}
	settings := outbound.Settings
	if settings == nil {
		settings = map[string]any{}
	}

	protocol := strings.ToLower(outbound.Protocol)
	switch protocol {
	case "vless", "vmess":
		endpoint := firstMap(settings["vnext"])
		if endpoint == nil {
			endpoint = settings
		}
		user := firstMap(endpoint["users"])
		if user == nil {
			user = endpoint
		}
		if err := xrayEndpoint(proxy, endpoint); err != nil {
			return nil, err
		}
		proxy["type"] = protocol
		proxy["uuid"] = mapString(user, "id")
		proxy["xudp"] = true
		if protocol == "vless" {
			if flow := mapString(user, "flow"); flow != "" {
				if strings.ToLower(flow) != Tvless.XRV {
					return nil, fmt.Errorf("unsupported flow %s", flow)
				}
				proxy["flow"] = Tvless.XRV
			}
			if encryption := mapString(user, "encryption"); encryption != "" {
				proxy["encryption"] = encryption
			}
		} else {
			proxy["alterId"] = mapInt(user, "alterId")
			proxy["cipher"] = "auto"
			if cipher := mapString(user, "security"); cipher != "" {
				proxy["cipher"] = cipher
			}
		}
	case "trojan":
		server := firstMap(settings["servers"])
		if server == nil {
			server = settings
		}
		if err := xrayEndpoint(proxy, server); err != nil {
			return nil, err
		}
		proxy["type"] = "trojan"
		proxy["password"] = mapString(server, "password")
	case "shadowsocks":
		server := firstMap(settings["servers"])
		if server == nil {
			server = settings
		}
		if err := xrayEndpoint(proxy, server); err != nil {
			return nil, err
		}
		proxy["type"] = "ss"
		proxy["cipher"] = mapString(server, "method")
		proxy["password"] = mapString(server, "password")
		if uot, _ := server["uot"].(bool); uot {
			proxy["udp-over-tcp"] = true
			if version := mapInt(server, "UoTVersion"); version > 0 {
				proxy["udp-over-tcp-version"] = version
			}
		}
	case "hysteria", "hysteria2":
		return convertXrayHysteria2(proxy, settings, stream)
	default:
		return nil, fmt.Errorf("unsupported protocol %s", protocol)
	}

	xrayTLS(proxy, stream, protocol)
	if err := xrayTransport(proxy, stream, protocol); err != nil {
		return nil, err
	}
	if protocol == "vless" || protocol == "trojan" {
		if fm, ok := stream["finalmask"].(map[string]any); ok {
			if block := finalMaskBlock(fm, proxy); block != nil {
				proxy["finalmask"] = block
			}
		}
	}
	return proxy, nil
}

// convertXrayHysteria2 reads the Xray-core fork's hysteria outbound: the
// server in settings, the auth in hysteriaSettings, the masks and QUIC
// parameters in finalmask.
func convertXrayHysteria2(proxy, settings, stream map[string]any) (map[string]any, error) {
	hysteria, _ := stream["hysteriaSettings"].(map[string]any)
	if hysteria == nil {
		hysteria = map[string]any{}
	}
	if version := mapInt(settings, "version"); version != 0 && version != 2 {
		return nil, fmt.Errorf("unsupported hysteria version %d", version)
	}
	if version := mapInt(hysteria, "version"); version != 0 && version != 2 {
		return nil, fmt.Errorf("unsupported hysteria version %d", version)
	}
	endpoint := settings
	if mapString(endpoint, "address") == "" {
		endpoint = hysteria
	}
	if err := xrayEndpoint(proxy, endpoint); err != nil {
		return nil, err
	}
	proxy["type"] = "hysteria2"
	if auth := mapString(hysteria, "auth"); auth != "" {
		proxy["password"] = auth
	}
	// The form before the fork moved these into finalmask.
	if up := xrayBandwidth(hysteria["up"]); up != "" {
		proxy["up"] = up
	}
	if down := xrayBandwidth(hysteria["down"]); down != "" {
		proxy["down"] = down
	}
	if fm, ok := stream["finalmask"].(map[string]any); ok {
		applyHysteria2FinalMask(proxy, fm)
	}
	// Older fork builds kept port hopping in hysteriaSettings.udphop.
	if hop, ok := hysteria["udphop"].(map[string]any); ok {
		applyUDPHop(proxy, hop)
	}
	if tls, ok := stream["tlsSettings"].(map[string]any); ok {
		if sni := mapString(tls, "serverName"); sni != "" {
			proxy["sni"] = sni
		}
		if alpn := stringList(tls["alpn"]); len(alpn) > 0 {
			proxy["alpn"] = alpn
		}
		if fp := mapString(tls, "fingerprint"); fp != "" {
			proxy["client-fingerprint"] = fp
		}
		xrayCertChecks(proxy, tls)
	}
	return proxy, nil
}

func xrayEndpoint(proxy, endpoint map[string]any) error {
	address := mapString(endpoint, "address")
	if address == "" {
		return errors.New("address is empty")
	}
	port := mapInt(endpoint, "port")
	if port <= 0 {
		return errors.New("port is empty")
	}
	proxy["server"] = address
	proxy["port"] = port
	return nil
}

// xrayTLS reads security, tlsSettings and realitySettings.
func xrayTLS(proxy, stream map[string]any, protocol string) {
	security := xraySecurity(stream)
	sniKey := "servername"
	if protocol == "trojan" {
		sniKey = "sni"
	}
	switch security {
	case "tls":
		tls, _ := stream["tlsSettings"].(map[string]any)
		proxy["tls"] = true
		proxy["client-fingerprint"] = "chrome"
		if tls == nil {
			return
		}
		if sni := mapString(tls, "serverName"); sni != "" {
			proxy[sniKey] = sni
		}
		if alpn := stringList(tls["alpn"]); len(alpn) > 0 {
			proxy["alpn"] = alpn
		}
		if fp := mapString(tls, "fingerprint"); fp != "" {
			proxy["client-fingerprint"] = fp
		}
		xrayCertChecks(proxy, tls)
		if ech := mapString(tls, "echConfigList"); ech != "" {
			proxy["ech-opts"] = echOptions(ech)
		}
	case "reality":
		reality, _ := stream["realitySettings"].(map[string]any)
		proxy["tls"] = true
		proxy["client-fingerprint"] = "chrome"
		if reality == nil {
			return
		}
		// The client fields come in several spellings: serverName or the
		// first of serverNames, publicKey or password (newer Xray), shortId
		// or the first of shortIds.
		if sni := firstString(reality, "serverName", "serverNames"); sni != "" {
			proxy[sniKey] = sni
		}
		if fp := mapString(reality, "fingerprint"); fp != "" {
			proxy["client-fingerprint"] = fp
		}
		if publicKey := firstString(reality, "publicKey", "password"); publicKey != "" {
			realityOpts := map[string]any{
				"public-key": publicKey,
				"short-id":   firstString(reality, "shortId", "shortIds"),
			}
			if pqv := mapString(reality, "mldsa65Verify"); pqv != "" {
				realityOpts["mldsa65-verify"] = pqv
			}
			proxy["reality-opts"] = realityOpts
		}
	}
}

// xraySecurity reads security as Xray does: xtls is tls, and a missing
// security with realitySettings present is reality.
func xraySecurity(stream map[string]any) string {
	security := strings.ToLower(strings.TrimSpace(mapString(stream, "security")))
	switch security {
	case "xtls":
		return "tls"
	case "":
		if reality, ok := stream["realitySettings"].(map[string]any); ok && len(reality) > 0 {
			return "reality"
		}
		return "none"
	}
	return security
}

// echOptions builds ech-opts from echConfigList. A URL (Xray fetches the
// list over DoH) or a list in another base64 alphabet would make the proxy
// fail to load; a URL turns ECH on and leaves the lookup to mihomo's DNS,
// another alphabet is re-encoded, anything else enables ECH alone.
func echOptions(list string) map[string]any {
	opts := map[string]any{"enable": true}
	list = strings.TrimSpace(list)
	if strings.HasPrefix(list, "http://") || strings.HasPrefix(list, "https://") {
		return opts
	}
	if _, err := base64.StdEncoding.DecodeString(list); err == nil {
		opts["config"] = list
	} else if raw, err := TryDecodeBase64(list); err == nil {
		opts["config"] = base64.StdEncoding.EncodeToString(raw)
	}
	return opts
}

// firstString reads a string key, else the first entry of a list key.
func firstString(m map[string]any, key, listKey string) string {
	if v := mapString(m, key); v != "" {
		return v
	}
	if list := stringList(m[listKey]); len(list) > 0 {
		return strings.TrimSpace(list[0])
	}
	return ""
}

// xrayCertChecks reads allowInsecure, pinnedPeerCertSha256 (the first of
// the list, as mihomo's fingerprint) and verifyPeerCertByName.
func xrayCertChecks(proxy, tls map[string]any) {
	if insecure, _ := tls["allowInsecure"].(bool); insecure {
		proxy["skip-cert-verify"] = true
	}
	if pinned := mapString(tls, "pinnedPeerCertSha256"); pinned != "" {
		first, _, _ := strings.Cut(pinned, ",")
		if pin := normalizeCertPin(first); pin != "" {
			proxy["fingerprint"] = pin
		} else {
			log.Warnln("pinnedPeerCertSha256 of %v is not a SHA-256 value, dropped", proxy["name"])
		}
	}
	if name := mapString(tls, "verifyPeerCertByName"); name != "" {
		proxy["name-cert-verify"] = name
	}
}

// xrayTransport reads network and the transport's settings into the
// network-opts block mihomo uses for it.
func xrayTransport(proxy, stream map[string]any, protocol string) error {
	network := strings.ToLower(mapString(stream, "network"))
	switch network {
	case "", "tcp", "raw":
		tcp, _ := stream["tcpSettings"].(map[string]any)
		if tcp == nil {
			tcp, _ = stream["rawSettings"].(map[string]any)
		}
		header, _ := tcp["header"].(map[string]any)
		if protocol != "trojan" && strings.ToLower(mapString(header, "type")) == "http" {
			request, _ := header["request"].(map[string]any)
			httpOpts := map[string]any{"path": []string{"/"}}
			headers := map[string]any{}
			if path := stringList(request["path"]); len(path) > 0 {
				httpOpts["path"] = path
			}
			if method := mapString(request, "method"); method != "" {
				httpOpts["method"] = method
			}
			if requestHeaders, ok := request["headers"].(map[string]any); ok {
				if host := stringList(requestHeaders["Host"]); len(host) > 0 {
					headers["Host"] = host
				}
			}
			httpOpts["headers"] = headers
			proxy["network"] = "http"
			proxy["http-opts"] = httpOpts
			return nil
		}
		proxy["network"] = "tcp"
	case "ws", "httpupgrade":
		ws, _ := stream[network+"Settings"].(map[string]any)
		headers := map[string]any{"User-Agent": RandUserAgent()}
		wsOpts := map[string]any{"path": "/"}
		if host := mapString(ws, "host"); host != "" {
			headers["Host"] = host
		}
		if wsHeaders, ok := ws["headers"].(map[string]any); ok {
			for key, value := range wsHeaders {
				if s, ok := value.(string); ok && s != "" {
					headers[key] = s
				}
			}
		}
		if path := mapString(ws, "path"); path != "" {
			pathURL, err := url.Parse(path)
			if err == nil {
				query := pathURL.Query()
				if earlyData := query.Get("ed"); earlyData != "" {
					if med, err := strconv.Atoi(earlyData); err == nil {
						wsOpts["max-early-data"] = med
						wsOpts["early-data-header-name"] = "Sec-WebSocket-Protocol"
						query.Del("ed")
						pathURL.RawQuery = query.Encode()
						path = pathURL.String()
					}
				}
				if earlyDataHeader := query.Get("eh"); earlyDataHeader != "" {
					wsOpts["early-data-header-name"] = earlyDataHeader
				}
			}
			wsOpts["path"] = path
		}
		if network == "httpupgrade" {
			wsOpts["v2ray-http-upgrade"] = true
			wsOpts["v2ray-http-upgrade-fast-open"] = true
		}
		wsOpts["headers"] = headers
		proxy["network"] = "ws"
		proxy["ws-opts"] = wsOpts
	case "grpc", "gun":
		grpc, _ := stream["grpcSettings"].(map[string]any)
		proxy["network"] = "grpc"
		proxy["grpc-opts"] = map[string]any{"grpc-service-name": mapString(grpc, "serviceName")}
	case "http", "h2":
		if protocol == "trojan" {
			return errors.New("trojan over h2 is not supported")
		}
		http, _ := stream["httpSettings"].(map[string]any)
		h2Opts := map[string]any{"path": "/"}
		if path := mapString(http, "path"); path != "" {
			h2Opts["path"] = path
		}
		if host := stringList(http["host"]); len(host) > 0 {
			h2Opts["host"] = host
		}
		proxy["network"] = "h2"
		proxy["h2-opts"] = h2Opts
	case "xhttp", "splithttp":
		if protocol != "vless" {
			return fmt.Errorf("%s over xhttp is not supported", protocol)
		}
		xhttp, _ := stream[network+"Settings"].(map[string]any)
		xhttpOpts := make(map[string]any)
		for _, key := range []string{"path", "host", "mode"} {
			if value := mapString(xhttp, key); value != "" {
				xhttpOpts[key] = value
			}
		}
		if xhttp != nil {
			// The fields Xray once took beside path and mode, then extra.
			parseXHTTPExtra(xhttp, xhttpOpts)
			parseXHTTPH2Flow(xhttp, xhttpOpts)
			if extra, ok := xhttp["extra"].(map[string]any); ok {
				parseXHTTPExtra(extra, xhttpOpts)
				parseXHTTPH2Flow(extra, xhttpOpts)
			}
		}
		proxy["network"] = "xhttp"
		proxy["xhttp-opts"] = xhttpOpts
	default:
		return fmt.Errorf("unsupported network %s", network)
	}
	return nil
}

func firstMap(v any) map[string]any {
	list, ok := v.([]any)
	if !ok || len(list) == 0 {
		return nil
	}
	m, _ := list[0].(map[string]any)
	return m
}

func mapString(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	switch v := m[key].(type) {
	case string:
		return v
	case float64:
		return strconv.FormatInt(int64(v), 10)
	}
	return ""
}

func mapInt(m map[string]any, key string) int {
	if m == nil {
		return 0
	}
	switch v := m[key].(type) {
	case float64:
		return int(v)
	case string:
		n, _ := strconv.Atoi(strings.TrimSpace(v))
		return n
	}
	return 0
}

// stringList reads a string, a comma-separated string or a list of strings.
func stringList(v any) []string {
	switch v := v.(type) {
	case string:
		if v == "" {
			return nil
		}
		return strings.Split(v, ",")
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}
