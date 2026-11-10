package convert_test

import (
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter"
	. "github.com/metacubex/mihomo/common/convert"
	"github.com/metacubex/mihomo/log"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The Xray JSON subscription of the Remnawave backend: an array of configs,
// each with remarks, meta.serverDescription and the server as the first
// outbound, followed by freedom, blackhole and dns.
const remnawaveXrayJSON = `[
{"remarks":"Нидерланды 🇳🇱","meta":null,"log":{"loglevel":"warning"},"outbounds":[
 {"tag":"proxy","protocol":"vless","settings":{"vnext":[{"address":"nl.example.com","port":443,"users":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none","flow":"xtls-rprx-vision"}]}]},
  "streamSettings":{"network":"tcp","tcpSettings":{},"security":"reality","realitySettings":{"serverName":"nl.example.com","publicKey":"ppQ9FwLrLIa0AOrp1WvcyiaQ37vg2WSy_CD4bIdiTUw","shortId":"6ba85179","fingerprint":"firefox","spiderX":"/"}}},
 {"tag":"direct","protocol":"freedom","settings":{}},
 {"tag":"block","protocol":"blackhole","settings":{}}]},
{"remarks":"Эстония 🇪🇪","meta":{"serverDescription":"Игры, YouTube "},"outbounds":[
 {"tag":"proxy","protocol":"hysteria","settings":{"address":"ee.example.com","port":443,"version":2},
  "streamSettings":{"network":"hysteria","hysteriaSettings":{"version":2,"auth":"letmein"},"security":"tls","tlsSettings":{"serverName":"ee.example.com","enableSessionResumption":false,"fingerprint":"firefox","alpn":["h3"]},
   "finalmask":{"quicParams":{"debug":false,"congestion":"bbr","brutalDown":"200m"},"udp":[{"type":"salamander","settings":{"password":"obfs-pw"}}]}}}]},
{"remarks":"XHTTP","outbounds":[
 {"tag":"proxy","protocol":"vless","settings":{"vnext":[{"address":"cdn.example.com","port":443,"users":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none","flow":""}]}]},
  "streamSettings":{"network":"xhttp","xhttpSettings":{"mode":"packet-up","host":"cdn.example.com","path":"/x","extra":{"xmux":{"maxConcurrency":"16-32","hMaxRequestTimes":"600-900"},"xPaddingBytes":"100-1000","scMaxEachPostBytes":1000000,"uplinkHTTPMethod":"GET","h2Flow":{"enabled":true}}},
   "security":"tls","tlsSettings":{"serverName":"cdn.example.com","fingerprint":"chrome","alpn":["h2","http/1.1"],"pinnedPeerCertSha256":"ab:cd,ef","verifyPeerCertByName":"real.example.com","echConfigList":"AEX+DQBBqwAgACA="},
   "finalmask":{"tcp":[{"type":"fragment","settings":{"packets":"tlshello","lengths":["1-1"],"delays":["0"]}}],"udp":[{"type":"noise","settings":{"noise":[{"rand":"10-20"}]}}]}}}]},
{"remarks":"WS","outbounds":[
 {"tag":"proxy","protocol":"trojan","settings":{"servers":[{"address":"ws.example.com","port":443,"password":"pw"}]},
  "streamSettings":{"network":"ws","wsSettings":{"path":"/ws?ed=2048","host":"ws.example.com","headers":{},"heartbeatPeriod":10},"security":"tls","tlsSettings":{"serverName":"ws.example.com","fingerprint":"chrome"},
   "finalmask":{"tcp":[{"type":"sudoku","settings":{"password":"p","customTables":["xpxvvpvv"],"paddingMin":10,"paddingMax":30}}]}}}]},
{"remarks":"gRPC","outbounds":[
 {"tag":"proxy","protocol":"vless","settings":{"vnext":[{"address":"grpc.example.com","port":443,"users":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"}]}]},
  "streamSettings":{"network":"grpc","grpcSettings":{"serviceName":"grpc","authority":"a.example.com","mode":false},"security":"reality","realitySettings":{"serverName":"grpc.example.com","publicKey":"ppQ9FwLrLIa0AOrp1WvcyiaQ37vg2WSy_CD4bIdiTUw","shortId":"","fingerprint":"chrome"}}}]},
{"remarks":"HTTPUpgrade","outbounds":[
 {"tag":"proxy","protocol":"vless","settings":{"vnext":[{"address":"hu.example.com","port":8080,"users":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"}]}]},
  "streamSettings":{"network":"httpupgrade","httpupgradeSettings":{"path":"/hu","host":"hu.example.com","headers":{"X-A":"b"}},"security":"none"}}]},
{"remarks":"HTTP header","outbounds":[
 {"tag":"proxy","protocol":"vless","settings":{"vnext":[{"address":"h.example.com","port":80,"users":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"}]}]},
  "streamSettings":{"network":"tcp","tcpSettings":{"header":{"type":"http","request":{"path":["/edge"],"headers":{"Host":["cdn.example.com"]}}}},"security":"none"}}]},
{"remarks":"SS","outbounds":[
 {"tag":"proxy","protocol":"shadowsocks","settings":{"servers":[{"address":"ss.example.com","port":8388,"password":"pw","method":"aes-256-gcm","uot":true,"UoTVersion":2}]},
  "streamSettings":{"network":"tcp","tcpSettings":{},"security":"none"}}]},
{"remarks":"VMess","outbounds":[
 {"tag":"proxy","protocol":"vmess","settings":{"vnext":[{"address":"vm.example.com","port":443,"users":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811","alterId":0,"security":"auto"}]}]},
  "streamSettings":{"network":"ws","wsSettings":{"path":"/vm"},"security":"tls","tlsSettings":{"serverName":"vm.example.com"}}}]},
{"remarks":"KCP xdns","outbounds":[
 {"tag":"proxy","protocol":"vless","settings":{"vnext":[{"address":"77.88.8.8","port":53,"users":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none","flow":""}]}]},
  "streamSettings":{"network":"kcp","kcpSettings":{"mtu":77,"tti":100,"congestion":false},"security":"none",
   "finalmask":{"udp":[{"type":"xdns","settings":{"resolvers":["t.example.com:aaaa+udp://77.88.8.8:53","t.example.com:aaaa+udp://8.8.8.8:53"]}}]}}}]},
{"remarks":"KCP seed unsupported","outbounds":[
 {"tag":"proxy","protocol":"vless","settings":{"vnext":[{"address":"kcp.example.com","port":443,"users":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"}]}]},
  "streamSettings":{"network":"kcp","kcpSettings":{"mtu":1350,"tti":50,"congestion":false,"seed":"old"},"security":"none"}}]}
]`

func TestConvertsXrayJSONRemnawave(t *testing.T) {
	proxies, err := ConvertsXrayJSON([]byte(remnawaveXrayJSON))
	require.NoError(t, err)
	byName := map[string]map[string]any{}
	for _, p := range proxies {
		byName[p["name"].(string)] = p
		_, err := adapter.ParseProxy(p)
		require.NoError(t, err, p["name"])
	}
	assert.Len(t, proxies, 10)
	assert.NotContains(t, byName, "KCP seed unsupported")

	kcp := byName["KCP xdns"]
	assert.Equal(t, "vless", kcp["type"])
	assert.Equal(t, "mkcp", kcp["network"])
	assert.Equal(t, map[string]any{"mtu": 77, "tti": 100}, kcp["mkcp-opts"])
	assert.Equal(t, map[string]any{"udp": []any{map[string]any{"type": "xdns", "settings": map[string]any{"resolvers": []any{
		"t.example.com:aaaa+udp://77.88.8.8:53", "t.example.com:aaaa+udp://8.8.8.8:53",
	}}}}}, kcp["finalmask"])

	nl := byName["Нидерланды 🇳🇱"]
	assert.Equal(t, "vless", nl["type"])
	assert.Equal(t, "nl.example.com", nl["server"])
	assert.Equal(t, 443, nl["port"])
	assert.Equal(t, "xtls-rprx-vision", nl["flow"])
	assert.Equal(t, "tcp", nl["network"])
	assert.Equal(t, true, nl["tls"])
	assert.Equal(t, "nl.example.com", nl["servername"])
	assert.Equal(t, "firefox", nl["client-fingerprint"])
	assert.Equal(t, map[string]any{"public-key": "ppQ9FwLrLIa0AOrp1WvcyiaQ37vg2WSy_CD4bIdiTUw", "short-id": "6ba85179"}, nl["reality-opts"])
	assert.NotContains(t, nl, "serverDescription")
	assert.NotContains(t, nl, "finalmask")

	ee := byName["Эстония 🇪🇪"]
	assert.Equal(t, "hysteria2", ee["type"])
	assert.Equal(t, "letmein", ee["password"])
	assert.Equal(t, "Игры, YouTube ", ee["serverDescription"])
	assert.Equal(t, "ee.example.com", ee["sni"])
	assert.Equal(t, []string{"h3"}, ee["alpn"])
	assert.Equal(t, "salamander", ee["obfs"])
	assert.Equal(t, "obfs-pw", ee["obfs-password"])
	assert.Equal(t, "209715200 bps", ee["down"])
	assert.NotContains(t, ee, "up")

	x := byName["XHTTP"]
	assert.Equal(t, "xhttp", x["network"])
	assert.Equal(t, []string{"h2", "http/1.1"}, x["alpn"])
	assert.NotContains(t, x, "fingerprint") // "ab:cd,ef" is not a SHA-256 pin
	assert.Equal(t, "real.example.com", x["name-cert-verify"])
	assert.Equal(t, map[string]any{"enable": true, "config": "AEX+DQBBqwAgACA="}, x["ech-opts"])
	xo := x["xhttp-opts"].(map[string]any)
	assert.Equal(t, "/x", xo["path"])
	assert.Equal(t, "cdn.example.com", xo["host"])
	assert.Equal(t, "packet-up", xo["mode"])
	assert.Equal(t, "100-1000", xo["x-padding-bytes"])
	assert.Equal(t, "GET", xo["uplink-http-method"])
	assert.Equal(t, 1000000, xo["sc-max-each-post-bytes"])
	assert.Equal(t, map[string]any{"max-concurrency": "16-32", "h-max-request-times": "600-900"}, xo["reuse-settings"])
	assert.Equal(t, map[string]any{"enabled": true}, xo["h2-flow"])
	fm := x["finalmask"].(map[string]any)
	assert.Len(t, fm["tcp"], 1)
	assert.NotContains(t, fm, "udp") // h2, not h3

	ws := byName["WS"]
	assert.Equal(t, "trojan", ws["type"])
	assert.Equal(t, "pw", ws["password"])
	assert.Equal(t, "ws.example.com", ws["sni"])
	assert.Equal(t, "ws", ws["network"])
	wo := ws["ws-opts"].(map[string]any)
	assert.Equal(t, "/ws", wo["path"])
	assert.Equal(t, 2048, wo["max-early-data"])
	assert.Equal(t, "Sec-WebSocket-Protocol", wo["early-data-header-name"])
	assert.Equal(t, "ws.example.com", wo["headers"].(map[string]any)["Host"])
	assert.Len(t, ws["finalmask"].(map[string]any)["tcp"], 1)

	g := byName["gRPC"]
	assert.Equal(t, "grpc", g["network"])
	assert.Equal(t, map[string]any{"grpc-service-name": "grpc"}, g["grpc-opts"])
	assert.Equal(t, map[string]any{"public-key": "ppQ9FwLrLIa0AOrp1WvcyiaQ37vg2WSy_CD4bIdiTUw", "short-id": ""}, g["reality-opts"])

	hu := byName["HTTPUpgrade"]
	assert.Equal(t, "ws", hu["network"])
	huo := hu["ws-opts"].(map[string]any)
	assert.Equal(t, "/hu", huo["path"])
	assert.Equal(t, true, huo["v2ray-http-upgrade"])
	assert.Equal(t, "b", huo["headers"].(map[string]any)["X-A"])
	assert.Equal(t, "hu.example.com", huo["headers"].(map[string]any)["Host"])
	assert.NotContains(t, hu, "tls")

	h := byName["HTTP header"]
	assert.Equal(t, "http", h["network"])
	assert.Equal(t, map[string]any{"path": []string{"/edge"}, "headers": map[string]any{"Host": []string{"cdn.example.com"}}}, h["http-opts"])

	ss := byName["SS"]
	assert.Equal(t, "ss", ss["type"])
	assert.Equal(t, "aes-256-gcm", ss["cipher"])
	assert.Equal(t, true, ss["udp-over-tcp"])
	assert.Equal(t, 2, ss["udp-over-tcp-version"])

	vm := byName["VMess"]
	assert.Equal(t, "vmess", vm["type"])
	assert.Equal(t, 0, vm["alterId"])
	assert.Equal(t, "auto", vm["cipher"])
	assert.Equal(t, "vm.example.com", vm["servername"])
	assert.Equal(t, "/vm", vm["ws-opts"].(map[string]any)["path"])
}

// A single Xray config converts every proxy outbound, named by tag.
func TestConvertsXrayJSONSingleConfig(t *testing.T) {
	config := `{"outbounds":[
 {"tag":"a","protocol":"vless","settings":{"vnext":[{"address":"a.example.com","port":443,"users":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"}]}]},"streamSettings":{"network":"tcp","security":"none"}},
 {"tag":"direct","protocol":"freedom"},
 {"tag":"b","protocol":"trojan","settings":{"servers":[{"address":"b.example.com","port":443,"password":"pw"}]},"streamSettings":{"network":"tcp","security":"tls","tlsSettings":{"serverName":"b.example.com","allowInsecure":true}}}
]}`
	proxies, err := ConvertsXrayJSON([]byte(config))
	require.NoError(t, err)
	require.Len(t, proxies, 2)
	assert.Equal(t, "a", proxies[0]["name"])
	assert.Equal(t, "b", proxies[1]["name"])
	assert.Equal(t, true, proxies[1]["skip-cert-verify"])
	for _, p := range proxies {
		_, err := adapter.ParseProxy(p)
		require.NoError(t, err)
	}

	// Duplicate remarks get unique names, as links do.
	two := `[{"remarks":"same","outbounds":[{"tag":"proxy","protocol":"vless","settings":{"vnext":[{"address":"a.example.com","port":443,"users":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811"}]}]}}]},
{"remarks":"same","outbounds":[{"tag":"proxy","protocol":"vless","settings":{"vnext":[{"address":"b.example.com","port":443,"users":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811"}]}]}}]}]`
	proxies, err = ConvertsXrayJSON([]byte(two))
	require.NoError(t, err)
	assert.Equal(t, "same", proxies[0]["name"])
	assert.Equal(t, "same-01", proxies[1]["name"])

	_, err = ConvertsXrayJSON([]byte(`[{"remarks":"x","outbounds":[{"protocol":"freedom"}]}]`))
	assert.Error(t, err)
	_, err = ConvertsXrayJSON([]byte(`vless://x`))
	assert.Error(t, err)
	_, err = ConvertsXrayJSON([]byte(`[{"remarks":`))
	assert.Error(t, err)
}

// The spellings and forms that would otherwise lose or break a node: REALITY
// keys under password/serverNames/shortIds, security xtls or missing, an ECH
// list given as a URL or in URL-safe base64, a certificate pin in base64 or
// hex with colons, port hopping under quicParams.udpHop or
// hysteriaSettings.udphop, and the whole subscription wrapped in base64.
func TestConvertsXrayJSONResilience(t *testing.T) {
	pinHex := "65b3acd7db555768304a16abb6f4366c1a0c0bb5cec81429617f0150d7d66726"
	pinRaw, _ := hex.DecodeString(pinHex)
	pinB64 := base64.StdEncoding.EncodeToString(pinRaw)
	echRaw := []byte{0x00, 0x45, 0xfe, 0x0d, 0x00, 0x41, 0xab, 0xff}
	echURL := base64.RawURLEncoding.EncodeToString(echRaw)
	echStd := base64.StdEncoding.EncodeToString(echRaw)

	sub := `[
{"remarks":"reality-password","outbounds":[{"tag":"proxy","protocol":"vless","settings":{"vnext":[{"address":"a.example.com","port":443,"users":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none","flow":"xtls-rprx-vision"}]}]},
  "streamSettings":{"network":"tcp","realitySettings":{"serverNames":["sni.example.com","other"],"password":"ppQ9FwLrLIa0AOrp1WvcyiaQ37vg2WSy_CD4bIdiTUw","shortIds":["6ba85179","00"],"fingerprint":"chrome"}}}]},
{"remarks":"xtls","outbounds":[{"tag":"proxy","protocol":"vless","settings":{"vnext":[{"address":"b.example.com","port":443,"users":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811"}]}]},
  "streamSettings":{"network":"tcp","security":"xtls","tlsSettings":{"serverName":"b.example.com","pinnedPeerCertSha256":"` + pinB64 + `","echConfigList":"https://1.1.1.1/dns-query"}}}]},
{"remarks":"pin-colons","outbounds":[{"tag":"proxy","protocol":"trojan","settings":{"servers":[{"address":"c.example.com","port":443,"password":"pw"}]},
  "streamSettings":{"network":"tcp","security":"tls","tlsSettings":{"serverName":"c.example.com","pinnedPeerCertSha256":"65:B3:AC:D7:DB:55:57:68:30:4A:16:AB:B6:F4:36:6C:1A:0C:0B:B5:CE:C8:14:29:61:7F:01:50:D7:D6:67:26,ab","echConfigList":"` + echURL + `"}}}]},
{"remarks":"pin-bad","outbounds":[{"tag":"proxy","protocol":"trojan","settings":{"servers":[{"address":"d.example.com","port":443,"password":"pw"}]},
  "streamSettings":{"network":"tcp","security":"tls","tlsSettings":{"serverName":"d.example.com","pinnedPeerCertSha256":"not-a-pin","echConfigList":"not base64!"}}}]},
{"remarks":"hop-quic","outbounds":[{"tag":"proxy","protocol":"hysteria","settings":{"address":"e.example.com","port":443,"version":2},
  "streamSettings":{"network":"hysteria","hysteriaSettings":{"version":2,"auth":"pw"},"security":"tls","tlsSettings":{"serverName":"e.example.com"},
   "finalmask":{"quicParams":{"udpHop":{"ports":"20000-30000","interval":"30s"}}}}}]},
{"remarks":"hop-legacy","outbounds":[{"tag":"proxy","protocol":"hysteria","settings":{"address":"f.example.com","port":443,"version":2},
  "streamSettings":{"network":"hysteria","hysteriaSettings":{"version":2,"auth":"pw","udphop":{"port":"443,5000-6000","interval":15}},"security":"tls","tlsSettings":{"serverName":"f.example.com"}}}]}
]`
	for _, input := range []string{sub, base64.StdEncoding.EncodeToString([]byte(sub)) + "\n"} {
		require.True(t, IsXrayJSON([]byte(input)))
		proxies, err := ConvertsXrayJSON([]byte(input))
		require.NoError(t, err)
		require.Len(t, proxies, 6)
		byName := map[string]map[string]any{}
		for _, p := range proxies {
			byName[p["name"].(string)] = p
			_, err := adapter.ParseProxy(p)
			require.NoError(t, err, p["name"])
		}

		r := byName["reality-password"]
		assert.Equal(t, true, r["tls"])
		assert.Equal(t, "sni.example.com", r["servername"])
		assert.Equal(t, map[string]any{"public-key": "ppQ9FwLrLIa0AOrp1WvcyiaQ37vg2WSy_CD4bIdiTUw", "short-id": "6ba85179"}, r["reality-opts"])
		assert.Equal(t, "xtls-rprx-vision", r["flow"])

		x := byName["xtls"]
		assert.Equal(t, true, x["tls"])
		assert.Equal(t, pinHex, x["fingerprint"])
		assert.Equal(t, map[string]any{"enable": true}, x["ech-opts"])

		c := byName["pin-colons"]
		assert.Equal(t, pinHex, c["fingerprint"])
		assert.Equal(t, map[string]any{"enable": true, "config": echStd}, c["ech-opts"])

		d := byName["pin-bad"]
		assert.NotContains(t, d, "fingerprint")
		assert.Equal(t, map[string]any{"enable": true}, d["ech-opts"])

		assert.Equal(t, "20000-30000", byName["hop-quic"]["ports"])
		assert.Equal(t, "30", byName["hop-quic"]["hop-interval"])
		assert.Equal(t, "443,5000-6000", byName["hop-legacy"]["ports"])
		assert.Equal(t, "15", byName["hop-legacy"]["hop-interval"])
	}
	assert.False(t, IsXrayJSON([]byte("vless://x@y:1#z")))
	assert.False(t, IsXrayJSON([]byte(base64.StdEncoding.EncodeToString([]byte("vless://x@y:1#z")))))
}

const xdriveXrayJSON = `{"remarks":"XD","outbounds":[
 {"tag":"proxy","protocol":"vless","mux":{"enabled":true,"concurrency":16,"xudpConcurrency":16,"xudpProxyUDP443":"reject"},
  "settings":{"address":"www.google.com","port":443,"id":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"mlkem768x25519plus.native.0rtt.gWPtAUIX9CGNQhiWit9Zty9ryz8kQKMiXkzjtC_sxSA"},
  "streamSettings":{"network":"xdrive","security":"tls","address":"1.2.3.4","port":443,
   "tlsSettings":{"serverName":"www.google.com","alpn":["h2"],"fingerprint":"chrome"},
   "xdriveSettings":{"service":"google-drive","remoteFolder":"folderId","secrets":["client","secret","refresh"],"eagerWindowMs":10000,"concurrency":32,
    "xmux":{"maxConnections":"2-4","hKeepAlivePeriod":30}}}}]}`

func TestConvertsXrayJSONXDrive(t *testing.T) {
	proxies, err := ConvertsXrayJSON([]byte(xdriveXrayJSON))
	require.NoError(t, err)
	require.Len(t, proxies, 1)
	p := proxies[0]
	assert.Equal(t, "vless", p["type"])
	assert.Equal(t, "xdrive", p["network"])
	assert.Equal(t, "mlkem768x25519plus.native.0rtt.gWPtAUIX9CGNQhiWit9Zty9ryz8kQKMiXkzjtC_sxSA", p["encryption"])
	assert.Equal(t, true, p["tls"])
	assert.Equal(t, []string{"h2"}, p["alpn"])
	assert.Equal(t, map[string]any{"enabled": true, "max-concurrency": 16, "xudp-concurrency": 16, "xudp-proxy-udp443": "reject"}, p["mux.cool"])
	assert.Equal(t, map[string]any{
		"service":         "google-drive",
		"remote-folder":   "folderId",
		"secrets":         []string{"client", "secret", "refresh"},
		"eager-window-ms": 10000,
		"concurrency":     32,
		"reuse-settings":  map[string]any{"max-connections": "2-4", "h-keep-alive-period": 30},
		"address":         "1.2.3.4",
		"port":            443,
	}, p["xdrive-opts"])
	_, err = adapter.ParseProxy(p)
	require.NoError(t, err)
}

func TestConvertsXrayJSONXDriveServices(t *testing.T) {
	const template = `{"flatten":true,"auth":{"type":"oauth2","tokenUrl":"https://t/x","form":{"client_id":"{secret0}"},"tokenPath":"a.b","expiryPath":"exp","header":{"Authorization":"Bearer {token}"}},
	 "put":{"method":"PUT","url":"https://d/{name}"},"get":{"url":"https://d/{name}","hrefPath":"href","hrefMethod":"GET"},"delete":{"method":"DELETE","url":"https://d/{name}"},
	 "list":{"url":"https://d/?p={prefix}","namesRegex":"<a>([^<]+)"},"retry":{"status":[429],"rateReason":"reason"}}`
	config := func(settings string, mux string) string {
		return `{"remarks":"x","outbounds":[{"protocol":"vless","mux":` + mux + `,"settings":{"address":"a.example.com","port":443,"id":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"mlkem768x25519plus.native.0rtt.gWPtAUIX9CGNQhiWit9Zty9ryz8kQKMiXkzjtC_sxSA"},"streamSettings":{"network":"xdrive","xdriveSettings":` + settings + `}}]}`
	}
	proxies, err := ConvertsXrayJSON([]byte(config(`{"service":"template","remoteFolder":"f","secrets":["s"],"template":`+template+`}`, `{"enabled":true}`)))
	require.NoError(t, err)
	opts := proxies[0]["xdrive-opts"].(map[string]any)
	tmpl := opts["template"].(map[string]any)
	assert.Equal(t, true, tmpl["flatten"])
	auth := tmpl["auth"].(map[string]any)
	assert.Equal(t, "https://t/x", auth["token-url"])
	assert.Equal(t, "a.b", auth["token-path"])
	assert.Equal(t, map[string]any{"Authorization": "Bearer {token}"}, auth["header"])
	assert.Equal(t, "href", tmpl["get"].(map[string]any)["href-path"])
	assert.Equal(t, "<a>([^<]+)", tmpl["list"].(map[string]any)["names-regex"])
	assert.Equal(t, "reason", tmpl["retry"].(map[string]any)["rate-reason"])
	_, err = adapter.ParseProxy(proxies[0])
	require.NoError(t, err)

	proxies, err = ConvertsXrayJSON([]byte(config(`{"service":"s3","remoteFolder":"prefix","secrets":["AK","SK"],"s3":{"endpoint":"https://s3.example.com","region":"eu","bucket":"b1","pathStyle":false}}`, `{"enabled":true}`)))
	require.NoError(t, err)
	assert.Equal(t, map[string]any{"endpoint": "https://s3.example.com", "region": "eu", "bucket": "b1", "path-style": false}, proxies[0]["xdrive-opts"].(map[string]any)["s3"])
	_, err = adapter.ParseProxy(proxies[0])
	require.NoError(t, err)

	// Xray-core refuses xdrive without mux, and so does a converter.
	_, err = ConvertsXrayJSON([]byte(config(`{"service":"local","remoteFolder":"/tmp/x"}`, `{"enabled":false}`)))
	assert.Error(t, err)
}

func TestConvertsV2RayVlessXDrive(t *testing.T) {
	link := "vless://b831381d-6324-4d53-ad4f-8cda48b30811@www.google.com:443?encryption=mlkem768x25519plus.native.0rtt.gWPtAUIX9CGNQhiWit9Zty9ryz8kQKMiXkzjtC_sxSA&type=xdrive&service=google-drive&remoteFolder=folderId&secrets=a,b,c&extra=" + url.QueryEscape(`{"eagerWindowMs":10000}`) + "&security=tls&sni=www.google.com&alpn=h2#xd"
	proxies, err := ConvertsV2Ray([]byte(link))
	require.NoError(t, err)
	require.Len(t, proxies, 1)
	p := proxies[0]
	assert.Equal(t, "xdrive", p["network"])
	assert.Equal(t, map[string]any{"enabled": true}, p["mux.cool"])
	assert.Equal(t, map[string]any{"service": "google-drive", "remote-folder": "folderId", "secrets": []string{"a", "b", "c"}, "eager-window-ms": 10000}, p["xdrive-opts"])
	_, err = adapter.ParseProxy(p)
	require.NoError(t, err)

	_, err = ConvertsV2Ray([]byte("vmess://b831381d-6324-4d53-ad4f-8cda48b30811@a.example.com:443?type=xdrive&service=local&remoteFolder=/tmp/x#x"))
	assert.Error(t, err)
}

// A share link that fails to convert is logged without its query and user
// info: for xdrive the query holds the OAuth client and refresh token.
func TestConvertsV2RayXDriveErrorLogHidesSecrets(t *testing.T) {
	sub := log.Subscribe()
	defer log.UnSubscribe(sub)

	const secret = "1//0refresh-token-secret"
	for _, link := range []string{
		// no service: the converter refuses it
		"vless://b831381d-6324-4d53-ad4f-8cda48b30811@www.google.com:443?encryption=mlkem768x25519plus.native.0rtt.x&type=xdrive&remoteFolder=f&secrets=id,client-secret," + url.QueryEscape(secret) + "#xd",
		"vmess://b831381d-6324-4d53-ad4f-8cda48b30811@www.google.com:443?type=xdrive&service=google-drive&remoteFolder=f&secrets=id,client-secret," + url.QueryEscape(secret) + "#xd",
	} {
		_, _ = ConvertsV2Ray([]byte(link))
	}

	warnings := 0
	timeout := time.After(time.Second)
	for warnings < 2 {
		select {
		case event := <-sub:
			if strings.Contains(event.Payload, "refresh-token-secret") || strings.Contains(event.Payload, "client-secret") ||
				strings.Contains(event.Payload, "b831381d") {
				t.Fatalf("a secret reached the log: %s", event.Payload)
			}
			if event.LogLevel == log.WARNING && strings.Contains(event.Payload, "xdrive") {
				warnings++
			}
		case <-timeout:
			t.Fatalf("%d of 2 warnings logged", warnings)
		}
	}
}
