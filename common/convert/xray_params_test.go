package convert_test

import (
	"encoding/base64"
	"net/url"
	"testing"

	"github.com/metacubex/mihomo/adapter"
	. "github.com/metacubex/mihomo/common/convert"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const remnawaveFM = `{"tcp":[{"type":"fragment","settings":{"packets":"tlshello","lengths":["1-1"],"delays":["0"]}},{"type":"header-custom","settings":{"clients":[[{"type":"str","packet":"GET / HTTP/1.1\r\nX-N: "},{"rand":8,"randRange":"97-122","capture":"n"},{"type":"str","packet":"\r\n\r\n"}]],"servers":[[{"reuse":"n"}]]}}],"udp":[{"type":"noise","settings":{"noise":[{"rand":"10-20","randRange":"0-255"}]}},{"type":"udphop","settings":{"mode":"intervalLocal","interval":"10-20","remotePorts":["443","20000-30000"]}}]}`

// A vless link as the Remnawave backend writes it for Happ: fm with the
// Xray finalmask, pqv, vcn, and the server description after the remark.
func TestConvertsV2RayRemnawaveVless(t *testing.T) {
	description := base64.StdEncoding.EncodeToString([]byte("Игры, YouTube"))
	pqv := base64.RawURLEncoding.EncodeToString(make([]byte, 1952)) // an ML-DSA-65 key is 1952 bytes
	link := "vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443?encryption=none&flow=xtls-rprx-vision&type=tcp&security=reality&sni=example.com&fp=chrome&pbk=ppQ9FwLrLIa0AOrp1WvcyiaQ37vg2WSy_CD4bIdiTUw&sid=6ba85179&pqv=" + pqv + "&spx=%2F&fm=" + url.QueryEscape(remnawaveFM) + "#" + url.PathEscape("Эстония 🇪🇪") + "?serverDescription=" + description

	for _, input := range []string{link, base64.StdEncoding.EncodeToString([]byte(link + "\n"))} {
		proxies, err := ConvertsV2Ray([]byte(input))
		require.NoError(t, err)
		require.Len(t, proxies, 1)
		p := proxies[0]
		assert.Equal(t, "Эстония 🇪🇪", p["name"])
		assert.Equal(t, "Игры, YouTube", p["serverDescription"])
		assert.Equal(t, map[string]any{"public-key": "ppQ9FwLrLIa0AOrp1WvcyiaQ37vg2WSy_CD4bIdiTUw", "short-id": "6ba85179", "mldsa65-verify": pqv}, p["reality-opts"])
		fm, ok := p["finalmask"].(map[string]any)
		require.True(t, ok, "finalmask missing")
		assert.Len(t, fm["tcp"], 2)
		// udp masks are for xhttp over h3 only; a tcp proxy drops them.
		assert.NotContains(t, fm, "udp")

		proxy, err := adapter.ParseProxy(p)
		require.NoError(t, err)
		assert.Equal(t, "Эстония 🇪🇪", proxy.Name())
	}
}

func TestConvertsV2RayVlessXHTTPH3KeepsUDPMasks(t *testing.T) {
	link := "vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443?encryption=none&type=xhttp&path=%2Fx&mode=packet-up&security=tls&sni=example.com&alpn=h3&fm=" + url.QueryEscape(remnawaveFM) + "#h3"
	proxies, err := ConvertsV2Ray([]byte(link))
	require.NoError(t, err)
	fm := proxies[0]["finalmask"].(map[string]any)
	assert.Len(t, fm["tcp"], 2)
	assert.Len(t, fm["udp"], 2)
	_, err = adapter.ParseProxy(proxies[0])
	require.NoError(t, err)
}

// VLESS over mKCP through an xdns tunnel, as the Remnawave backend links it:
// type=kcp with mtu and tti, the first xdns in fm.
func TestConvertsV2RayVlessMKCPXDNS(t *testing.T) {
	fm := `{"udp":[{"type":"xdns","settings":{"resolvers":["t.example.com:aaaa+udp://77.88.8.8:53","t.example.com:aaaa+udp://8.8.8.8:53"]}}]}`
	link := "vless://b831381d-6324-4d53-ad4f-8cda48b30811@77.88.8.8:53?encryption=none&type=kcp&mtu=77&tti=100&security=none&fm=" + url.QueryEscape(fm) + "#dns"
	proxies, err := ConvertsV2Ray([]byte(link))
	require.NoError(t, err)
	require.Len(t, proxies, 1)
	p := proxies[0]
	assert.Equal(t, "mkcp", p["network"])
	assert.Equal(t, map[string]any{"mtu": 77, "tti": 100}, p["mkcp-opts"])
	assert.Len(t, p["finalmask"].(map[string]any)["udp"], 1)
	_, err = adapter.ParseProxy(p)
	require.NoError(t, err)

	// The mKCP before finalmask: header and seed have no place in VLESS.
	proxies, err = ConvertsV2Ray([]byte("vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443?type=kcp&headerType=wechat-video&seed=s#old"))
	assert.Error(t, err)
	assert.Empty(t, proxies)
}

func TestConvertsV2RayVlessTLSExtras(t *testing.T) {
	link := "vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443?encryption=none&type=xhttp&path=%2Fx&host=cdn.example.com&mode=packet-up&x_padding_bytes=100-1000&extra=" + url.QueryEscape(`{"uplinkHttpMethod":"GET","xPaddingBytes":"200-300"}`) + "&security=tls&sni=example.com&fp=firefox&alpn=h2&pcs=ab%3Acd&vcn=real.example.com#x"
	proxies, err := ConvertsV2Ray([]byte(link))
	require.NoError(t, err)
	p := proxies[0]
	assert.Equal(t, "real.example.com", p["name-cert-verify"])
	assert.Equal(t, "ab:cd", p["fingerprint"]) // not a SHA-256: passed through as the link gave it
	link = "vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443?type=tcp&security=tls&sni=example.com&pcs=65%3AB3%3AAC%3AD7%3ADB%3A55%3A57%3A68%3A30%3A4A%3A16%3AAB%3AB6%3AF4%3A36%3A6C%3A1A%3A0C%3A0B%3AB5%3ACE%3AC8%3A14%3A29%3A61%3A7F%3A01%3A50%3AD7%3AD6%3A67%3A26#pin"
	pinned, err := ConvertsV2Ray([]byte(link))
	require.NoError(t, err)
	assert.Equal(t, "65b3acd7db555768304a16abb6f4366c1a0c0bb5cec81429617f0150d7d66726", pinned[0]["fingerprint"])
	xhttp := p["xhttp-opts"].(map[string]any)
	assert.Equal(t, "GET", xhttp["uplink-http-method"])
	// extra wins over the x_padding_bytes shorthand.
	assert.Equal(t, "200-300", xhttp["x-padding-bytes"])
	assert.NotContains(t, p, "serverDescription")
	_, err = adapter.ParseProxy(p)
	require.NoError(t, err)

	// Invalid fm: the proxy stays, without masks.
	proxies, err = ConvertsV2Ray([]byte("vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443?type=tcp&security=none&fm=%7Bnot-json#bad"))
	require.NoError(t, err)
	assert.NotContains(t, proxies[0], "finalmask")
	// fm without tcp or udp chains: nothing to carry.
	proxies, err = ConvertsV2Ray([]byte("vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443?type=tcp&security=none&fm=%7B%22quicParams%22%3A%7B%7D%7D#empty"))
	require.NoError(t, err)
	assert.NotContains(t, proxies[0], "finalmask")
}

func TestConvertsV2RayTrojanRemnawave(t *testing.T) {
	link := "trojan://pass%40word@example.com:443?type=tcp&security=tls&sni=example.com&fp=chrome&vcn=real.example.com&fm=" + url.QueryEscape(`{"tcp":[{"type":"fragment","settings":{"packets":"tlshello","length":"1-1","delay":"0"}}]}`) + "#Trojan?serverDescription=" + base64.RawURLEncoding.EncodeToString([]byte("plain text"))
	proxies, err := ConvertsV2Ray([]byte(link))
	require.NoError(t, err)
	p := proxies[0]
	assert.Equal(t, "Trojan", p["name"])
	assert.Equal(t, "plain text", p["serverDescription"])
	assert.Equal(t, "real.example.com", p["name-cert-verify"])
	assert.Len(t, p["finalmask"].(map[string]any)["tcp"], 1)
	_, err = adapter.ParseProxy(p)
	require.NoError(t, err)
}

func TestConvertsV2RayHysteria2FinalMask(t *testing.T) {
	fm := `{"udp":[{"type":"salamander","settings":{"password":"obfs-pw"}},{"type":"udphop","settings":{"mode":"intervalLocal","interval":"10-20","remotePorts":["443","20000-30000"]}}],"quicParams":{"debug":false,"congestion":"bbr","bbrProfile":"balanced","brutalUp":"100m","brutalDown":200000000,"maxStreamReceiveWindow":"16777216","initConnectionReceiveWindow":33554432}}`
	link := "hysteria2://letmein@example.com:443/?sni=example.com&fm=" + url.QueryEscape(fm) + "#hy2"
	proxies, err := ConvertsV2Ray([]byte(link))
	require.NoError(t, err)
	p := proxies[0]
	assert.Equal(t, "salamander", p["obfs"])
	assert.Equal(t, "obfs-pw", p["obfs-password"])
	assert.Equal(t, "443,20000-30000", p["ports"])
	assert.Equal(t, "10-20", p["hop-interval"])
	assert.Equal(t, "104857600 bps", p["up"])
	assert.Equal(t, "200 Mbps", p["down"])
	assert.Equal(t, "balanced", p["bbr-profile"])
	assert.Equal(t, uint64(16777216), p["max-stream-receive-window"])
	assert.Equal(t, uint64(33554432), p["initial-connection-receive-window"])
	_, err = adapter.ParseProxy(p)
	require.NoError(t, err)

	// Port hopping under quicParams.udpHop, where Remnawave's mihomo
	// template reads it; the udphop mask wins when both are present.
	link = "hysteria2://letmein@example.com:443/?sni=example.com&fm=" + url.QueryEscape(`{"quicParams":{"udpHop":{"ports":20000,"interval":"20-40"}}}`) + "#quic-hop"
	proxies, err = ConvertsV2Ray([]byte(link))
	require.NoError(t, err)
	assert.Equal(t, "20000", proxies[0]["ports"])
	assert.Equal(t, "20-40", proxies[0]["hop-interval"])
	link = "hysteria2://letmein@example.com:443/?sni=example.com&fm=" + url.QueryEscape(`{"udp":[{"type":"udphop","settings":{"remotePorts":"5000-6000","interval":"10"}}],"quicParams":{"udpHop":{"ports":20000,"interval":"20-40"}}}`) + "#both"
	proxies, err = ConvertsV2Ray([]byte(link))
	require.NoError(t, err)
	assert.Equal(t, "5000-6000", proxies[0]["ports"])
	assert.Equal(t, "10", proxies[0]["hop-interval"])

	// gecko: salamander with a packet size; quicParams only, as Remnawave
	// links a plain server.
	link = "hysteria2://letmein@example.com:443/?sni=example.com&fm=" + url.QueryEscape(`{"udp":[{"type":"salamander","settings":{"password":"g","packetSize":"1200-1400"}}]}`) + "#gecko"
	proxies, err = ConvertsV2Ray([]byte(link))
	require.NoError(t, err)
	assert.Equal(t, "gecko", proxies[0]["obfs"])
	assert.Equal(t, 1200, proxies[0]["obfs-min-packet-size"])
	assert.Equal(t, 1400, proxies[0]["obfs-max-packet-size"])
	_, err = adapter.ParseProxy(proxies[0])
	require.NoError(t, err)

	link = "hysteria2://letmein@example.com:443/?sni=example.com&fm=%7B%22quicParams%22%3A%7B%22debug%22%3Afalse%2C%22congestion%22%3A%22bbr%22%7D%7D#plain"
	proxies, err = ConvertsV2Ray([]byte(link))
	require.NoError(t, err)
	assert.Equal(t, "", proxies[0]["obfs"])
	assert.NotContains(t, proxies[0], "ports")
	_, err = adapter.ParseProxy(proxies[0])
	require.NoError(t, err)
}

func TestConvertsV2RayServerDescriptionOnEveryScheme(t *testing.T) {
	desc := base64.StdEncoding.EncodeToString([]byte("note"))
	links := []string{
		"ss://" + base64.StdEncoding.EncodeToString([]byte("aes-256-gcm:pw")) + "@example.com:8388#ss?serverDescription=" + desc,
		"hysteria2://pw@example.com:443/?sni=example.com#hy2?serverDescription=" + desc,
		"vmess://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443?type=tcp&security=tls#vm?serverDescription=" + desc,
		"tuic://u:p@example.com:443?sni=example.com#tuic?serverDescription=" + desc,
	}
	for _, link := range links {
		proxies, err := ConvertsV2Ray([]byte(link))
		require.NoError(t, err, link)
		assert.Equal(t, "note", proxies[0]["serverDescription"], link)
		assert.NotContains(t, proxies[0]["name"], "serverDescription", link)
	}
}

func TestDecodeBase64Variants(t *testing.T) {
	link := "vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443?type=tcp&security=none#a?b"
	for name, encoded := range map[string]string{
		"std":        base64.StdEncoding.EncodeToString([]byte(link)),
		"raw":        base64.RawStdEncoding.EncodeToString([]byte(link)),
		"url":        base64.URLEncoding.EncodeToString([]byte(link + "\n" + link)),
		"raw-url":    base64.RawURLEncoding.EncodeToString([]byte(link)),
		"whitespace": "\n  " + base64.StdEncoding.EncodeToString([]byte(link)) + "\r\n",
		"bom":        "\xef\xbb\xbf" + base64.StdEncoding.EncodeToString([]byte(link)),
		"plain":      link,
	} {
		t.Run(name, func(t *testing.T) {
			proxies, err := ConvertsV2Ray([]byte(encoded))
			require.NoError(t, err)
			assert.Equal(t, "example.com", proxies[0]["server"])
		})
	}
}
