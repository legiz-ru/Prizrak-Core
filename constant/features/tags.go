package features

func Tags() (tags []string) {
	if CMFA {
		tags = append(tags, "cmfa")
	}
	if WithLowMemory {
		tags = append(tags, "with_low_memory")
	}
	if WithPowerSave {
		tags = append(tags, "with_powersave")
	}
	if NoFakeTCP {
		tags = append(tags, "no_fake_tcp")
	}
	if NoTailscale {
		tags = append(tags, "no_tailscale")
	}
	if NoZeroTier {
		tags = append(tags, "no_zerotier")
	}
	if NoEasyTier {
		tags = append(tags, "no_easytier")
	}
	if NoOpenVPN {
		tags = append(tags, "no_openvpn")
	}
	if NoMasque {
		tags = append(tags, "no_masque")
	}
	if NoMieru {
		tags = append(tags, "no_mieru")
	}
	if NoSudoku {
		tags = append(tags, "no_sudoku")
	}
	if NoTrustTunnel {
		tags = append(tags, "no_trusttunnel")
	}
	if NoShadowQuic {
		tags = append(tags, "no_shadowquic")
	}
	if NoSnell {
		tags = append(tags, "no_snell")
	}
	if NoSSR {
		tags = append(tags, "no_ssr")
	}
	if NoAnyTLS {
		tags = append(tags, "no_anytls")
	}
	if WithGVisor {
		tags = append(tags, "with_gvisor")
	}
	return
}
