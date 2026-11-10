package adapter

import (
	"fmt"

	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/common/structure"
	C "github.com/metacubex/mihomo/constant"
)

// The mux of Xray-core v26.11.9 for every outbound
// (app/proxyman/outbound/handler.go): a concurrency below 128 is raised to
// 128 and a connection carries at most 1024 streams in its life.
const (
	xdriveMinMuxConcurrency = 128
	xdriveMinMuxConnections = 1024
)

func ParseProxy(mapping map[string]any, options ...ProxyOption) (C.Proxy, error) {
	decoder := structure.NewDecoder(structure.Option{TagName: "proxy", WeaklyTypedInput: true, KeyReplacer: structure.DefaultKeyReplacer})
	proxyType, existType := mapping["type"].(string)
	if !existType {
		return nil, fmt.Errorf("missing type")
	}

	opt := applyProxyOptions(options...)
	basicOption := outbound.BasicOption{
		DialerForAPI: opt.DialerForAPI,
		TunnelForAPI: opt.TunnelForAPI,
		ProviderName: opt.ProviderName,
	}

	var (
		proxy outbound.ProxyAdapter
		err   error
	)
	switch proxyType {
	case "ss":
		ssOption := &outbound.ShadowSocksOption{BasicOption: basicOption}
		err = decoder.Decode(mapping, ssOption)
		if err != nil {
			break
		}
		proxy, err = outbound.NewShadowSocks(*ssOption)
	case "ssr":
		ssrOption := &outbound.ShadowSocksROption{BasicOption: basicOption}
		err = decoder.Decode(mapping, ssrOption)
		if err != nil {
			break
		}
		proxy, err = outbound.NewShadowSocksR(*ssrOption)
	case "socks5":
		socksOption := &outbound.Socks5Option{BasicOption: basicOption}
		err = decoder.Decode(mapping, socksOption)
		if err != nil {
			break
		}
		proxy, err = outbound.NewSocks5(*socksOption)
	case "http":
		httpOption := &outbound.HttpOption{BasicOption: basicOption}
		err = decoder.Decode(mapping, httpOption)
		if err != nil {
			break
		}
		proxy, err = outbound.NewHttp(*httpOption)
	case "vmess":
		vmessOption := &outbound.VmessOption{BasicOption: basicOption}
		err = decoder.Decode(mapping, vmessOption)
		if err != nil {
			break
		}
		proxy, err = outbound.NewVmess(*vmessOption)
	case "vless":
		vlessOption := &outbound.VlessOption{BasicOption: basicOption}
		err = decoder.Decode(mapping, vlessOption)
		if err != nil {
			break
		}
		proxy, err = outbound.NewVless(*vlessOption)
	case "snell":
		snellOption := &outbound.SnellOption{BasicOption: basicOption}
		err = decoder.Decode(mapping, snellOption)
		if err != nil {
			break
		}
		proxy, err = outbound.NewSnell(*snellOption)
	case "trojan":
		trojanOption := &outbound.TrojanOption{BasicOption: basicOption}
		err = decoder.Decode(mapping, trojanOption)
		if err != nil {
			break
		}
		proxy, err = outbound.NewTrojan(*trojanOption)
	case "hysteria":
		hyOption := &outbound.HysteriaOption{BasicOption: basicOption}
		err = decoder.Decode(mapping, hyOption)
		if err != nil {
			break
		}
		proxy, err = outbound.NewHysteria(*hyOption)
	case "hysteria2":
		hyOption := &outbound.Hysteria2Option{BasicOption: basicOption}
		err = decoder.Decode(mapping, hyOption)
		if err != nil {
			break
		}
		proxy, err = outbound.NewHysteria2(*hyOption)
	case "wireguard":
		wgOption := &outbound.WireGuardOption{BasicOption: basicOption}
		err = decoder.Decode(mapping, wgOption)
		if err != nil {
			break
		}
		proxy, err = outbound.NewWireGuard(*wgOption)
	case "tuic":
		tuicOption := &outbound.TuicOption{BasicOption: basicOption}
		err = decoder.Decode(mapping, tuicOption)
		if err != nil {
			break
		}
		proxy, err = outbound.NewTuic(*tuicOption)
	case "shadowquic":
		shadowQuicOption := &outbound.ShadowQuicOption{BasicOption: basicOption}
		err = decoder.Decode(mapping, shadowQuicOption)
		if err != nil {
			break
		}
		proxy, err = outbound.NewShadowQuic(*shadowQuicOption)
	case "gost-relay":
		relayOption := &outbound.GostRelayOption{BasicOption: basicOption}
		err = decoder.Decode(mapping, relayOption)
		if err != nil {
			break
		}
		proxy, err = outbound.NewGostRelay(*relayOption)
	case "direct":
		directOption := &outbound.DirectOption{BasicOption: basicOption}
		err = decoder.Decode(mapping, directOption)
		if err != nil {
			break
		}
		proxy = outbound.NewDirectWithOption(*directOption)
	case "freedom":
		freedomOption := &outbound.FreedomOption{BasicOption: basicOption}
		err = decoder.Decode(mapping, freedomOption)
		if err != nil {
			break
		}
		proxy, err = outbound.NewFreedom(*freedomOption)
	case "dns":
		dnsOptions := &outbound.DnsOption{BasicOption: basicOption}
		err = decoder.Decode(mapping, dnsOptions)
		if err != nil {
			break
		}
		proxy = outbound.NewDnsWithOption(*dnsOptions)
	case "reject":
		rejectOption := &outbound.RejectOption{BasicOption: basicOption}
		err = decoder.Decode(mapping, rejectOption)
		if err != nil {
			break
		}
		proxy = outbound.NewRejectWithOption(*rejectOption)
	case "rematch":
		rematchOption := &outbound.RematchOption{BasicOption: basicOption}
		err = decoder.Decode(mapping, rematchOption)
		if err != nil {
			break
		}
		proxy, err = outbound.NewRematch(*rematchOption)
	case "ssh":
		sshOption := &outbound.SshOption{BasicOption: basicOption}
		err = decoder.Decode(mapping, sshOption)
		if err != nil {
			break
		}
		proxy, err = outbound.NewSsh(*sshOption)
	case "mieru":
		mieruOption := &outbound.MieruOption{BasicOption: basicOption}
		err = decoder.Decode(mapping, mieruOption)
		if err != nil {
			break
		}
		proxy, err = outbound.NewMieru(*mieruOption)
	case "anytls":
		anytlsOption := &outbound.AnyTLSOption{BasicOption: basicOption}
		err = decoder.Decode(mapping, anytlsOption)
		if err != nil {
			break
		}
		proxy, err = outbound.NewAnyTLS(*anytlsOption)
	case "sudoku":
		sudokuOption := &outbound.SudokuOption{BasicOption: basicOption}
		err = decoder.Decode(mapping, sudokuOption)
		if err != nil {
			break
		}
		proxy, err = outbound.NewSudoku(*sudokuOption)
	case "masque":
		masqueOption := &outbound.MasqueOption{BasicOption: basicOption}
		err = decoder.Decode(mapping, masqueOption)
		if err != nil {
			break
		}
		proxy, err = outbound.NewMasque(*masqueOption)
	case "trusttunnel":
		trustTunnelOption := &outbound.TrustTunnelOption{BasicOption: basicOption}
		err = decoder.Decode(mapping, trustTunnelOption)
		if err != nil {
			break
		}
		proxy, err = outbound.NewTrustTunnel(*trustTunnelOption)
	case "openvpn":
		openVPNOption := &outbound.OpenVPNOption{BasicOption: basicOption}
		err = decoder.Decode(mapping, openVPNOption)
		if err != nil {
			break
		}
		proxy, err = outbound.NewOpenVPN(*openVPNOption)
	case "tailscale":
		tailscaleOption := &outbound.TailscaleOption{BasicOption: basicOption}
		err = decoder.Decode(mapping, tailscaleOption)
		if err != nil {
			break
		}
		proxy, err = outbound.NewTailscale(*tailscaleOption)
	case "zerotier":
		zeroTierOption := &outbound.ZeroTierOption{BasicOption: basicOption}
		err = decoder.Decode(mapping, zeroTierOption)
		if err != nil {
			break
		}
		proxy, err = outbound.NewZeroTier(*zeroTierOption)
	case "easytier":
		easyTierOption := &outbound.EasyTierOption{BasicOption: basicOption}
		err = decoder.Decode(mapping, easyTierOption)
		if err != nil {
			break
		}
		proxy, err = outbound.NewEasyTier(*easyTierOption)
	default:
		return nil, fmt.Errorf("unsupport proxy type: %s", proxyType)
	}

	if err != nil {
		return nil, err
	}

	muxOption := &outbound.SingMuxOption{}
	if muxMapping, muxExist := mapping["smux"].(map[string]any); muxExist {
		err = decoder.Decode(muxMapping, muxOption)
		if err != nil {
			return nil, err
		}
	}

	muxCoolOption := &outbound.MuxCoolOption{}
	if muxMapping, muxExist := mapping["mux.cool"].(map[string]any); muxExist {
		err = decoder.Decode(muxMapping, muxCoolOption)
		if err != nil {
			return nil, err
		}
	}
	if muxOption.Enabled && muxCoolOption.Enabled {
		return nil, fmt.Errorf("smux and mux.cool cannot be enabled together")
	}
	if proxyType == "vless" && mapping["network"] == "xdrive" {
		// As Xray-core refuses it: every connection would be a session of its
		// own, with a ring of objects to create on the storage.
		if !muxCoolOption.Enabled || muxCoolOption.XUDPProxyUDP443 == "skip" {
			return nil, fmt.Errorf(`xdrive needs "mux.cool" enabled and no "xudp-proxy-udp443": "skip"`)
		}
		// Xray-core raises a lower mux concurrency to this: a session is a ring
		// of objects and pollers, so as many streams as can share one should.
		if muxCoolOption.MaxConcurrency < xdriveMinMuxConcurrency {
			muxCoolOption.MaxConcurrency = xdriveMinMuxConcurrency
		}
		// Each carrier is a new session with a new ring on the storage, so it
		// should live as long as in Xray-core, not end after 128 streams.
		if muxCoolOption.MaxConnections < xdriveMinMuxConnections {
			muxCoolOption.MaxConnections = xdriveMinMuxConnections
		}
	}
	if muxOption.Enabled {
		proxy, err = outbound.NewSingMux(*muxOption, proxy)
		if err != nil {
			return nil, err
		}
	}
	if muxCoolOption.Enabled || muxCoolOption.MaxConcurrency < 0 || muxCoolOption.MaxConnections < 0 || muxCoolOption.MaxCarriers < 0 || muxCoolOption.XUDPConcurrency < 0 {
		proxy, err = outbound.NewMuxCool(*muxCoolOption, proxy)
		if err != nil {
			return nil, err
		}
	}

	proxy = outbound.NewAutoCloseProxyAdapter(proxy)

	if err := decoder.Decode(mapping, &basicOption); err == nil {
		udp443, err := resolveUdp443(basicOption.Udp443, basicOption.Quic)
		if err != nil {
			return nil, err
		}
		if udp443 == outbound.Udp443Reject {
			proxy = outbound.NewUdp443(proxy, udp443)
		}
	}
	return NewProxy(proxy), nil
}

// resolveUdp443 merges the udp-443 option with its `quic` alias.
func resolveUdp443(udp443, quic string) (string, error) {
	for _, v := range []string{udp443, quic} {
		switch v {
		case "", outbound.Udp443Allow, outbound.Udp443Reject:
		default:
			return "", fmt.Errorf("unsupport udp-443 value: %s", v)
		}
	}
	if udp443 != "" && quic != "" && udp443 != quic {
		return "", fmt.Errorf("conflicting udp-443 and quic values: %q != %q", udp443, quic)
	}
	if udp443 == "" {
		return quic, nil
	}
	return udp443, nil
}

type proxyOption struct {
	DialerForAPI C.Dialer
	TunnelForAPI C.Tunnel
	ProviderName string
}

func applyProxyOptions(options ...ProxyOption) proxyOption {
	opt := proxyOption{}
	for _, o := range options {
		o(&opt)
	}
	return opt
}

type ProxyOption func(opt *proxyOption)

func WithDialerForAPI(dialer C.Dialer) ProxyOption {
	return func(opt *proxyOption) {
		opt.DialerForAPI = dialer
	}
}

func WithTunnelForAPI(tunnel C.Tunnel) ProxyOption {
	return func(opt *proxyOption) {
		opt.TunnelForAPI = tunnel
	}
}

func WithProviderName(name string) ProxyOption {
	return func(opt *proxyOption) {
		opt.ProviderName = name
	}
}
