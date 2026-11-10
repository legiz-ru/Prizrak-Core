package inbound

import (
	"strings"

	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/listener/sing_vless"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/transport/finalmask/option"
	"github.com/metacubex/mihomo/transport/xdrive"
	"github.com/metacubex/mihomo/transport/xhttp"
)

type VlessOption struct {
	BaseOption
	Users           []VlessUser   `inbound:"users"`
	Decryption      string        `inbound:"decryption,omitempty"`
	WsPath          string        `inbound:"ws-path,omitempty"`
	XHTTPConfig     XHTTPConfig   `inbound:"xhttp-config,omitempty"`
	XDriveConfig    XDriveConfig  `inbound:"xdrive-config,omitempty"`
	GrpcServiceName string        `inbound:"grpc-service-name,omitempty"`
	Certificate     string        `inbound:"certificate,omitempty"`
	PrivateKey      string        `inbound:"private-key,omitempty"`
	ClientAuthType  string        `inbound:"client-auth-type,omitempty"`
	ClientAuthCert  string        `inbound:"client-auth-cert,omitempty"`
	EchKey          string        `inbound:"ech-key,omitempty"`
	AllowInsecure   bool          `inbound:"allow-insecure,omitempty"`
	ShadowTLS       ShadowTLS     `inbound:"shadow-tls,omitempty"`
	ResTLS          ResTLS        `inbound:"res-tls,omitempty"`
	JLSConfig       JLSConfig     `inbound:"jls-config,omitempty"`
	RealityConfig   RealityConfig `inbound:"reality-config,omitempty"`
	MuxOption       MuxOption     `inbound:"mux-option,omitempty"`
	FinalMask       option.Option `inbound:"finalmask,omitempty"`
}

type VlessUser struct {
	Username string `inbound:"username,omitempty"`
	UUID     string `inbound:"uuid"`
	Flow     string `inbound:"flow,omitempty"`
}

type XHTTPConfig struct {
	Path                 string `inbound:"path,omitempty"`
	Host                 string `inbound:"host,omitempty"`
	Mode                 string `inbound:"mode,omitempty"`
	XPaddingBytes        string `inbound:"x-padding-bytes,omitempty"`
	XPaddingObfsMode     bool   `inbound:"x-padding-obfs-mode,omitempty"`
	XPaddingKey          string `inbound:"x-padding-key,omitempty"`
	XPaddingHeader       string `inbound:"x-padding-header,omitempty"`
	XPaddingPlacement    string `inbound:"x-padding-placement,omitempty"`
	XPaddingMethod       string `inbound:"x-padding-method,omitempty"`
	UplinkHTTPMethod     string `inbound:"uplink-http-method,omitempty"`
	SessionPlacement     string `inbound:"session-placement,omitempty"`
	SessionKey           string `inbound:"session-key,omitempty"`
	SeqPlacement         string `inbound:"seq-placement,omitempty"`
	SeqKey               string `inbound:"seq-key,omitempty"`
	UplinkDataPlacement  string `inbound:"uplink-data-placement,omitempty"`
	UplinkDataKey        string `inbound:"uplink-data-key,omitempty"`
	UplinkChunkSize      string `inbound:"uplink-chunk-size,omitempty"`
	NoSSEHeader          bool   `inbound:"no-sse-header,omitempty"`
	ScStreamUpServerSecs string `inbound:"sc-stream-up-server-secs,omitempty"`
	ScMaxBufferedPosts   string `inbound:"sc-max-buffered-posts,omitempty"`
	ScMaxEachPostBytes   string `inbound:"sc-max-each-post-bytes,omitempty"`
	// Server only: Mux.Cool KeepAlive pokes of idle packet-up and stream-up
	// downlinks, the governor's server role and the HTTP/2 settings.
	MuxKeepAliveSecs  string                     `inbound:"mux-keep-alive-secs,omitempty"`
	MuxKeepAliveBytes string                     `inbound:"mux-keep-alive-bytes,omitempty"`
	H2Flow            *xhttp.H2FlowServerOptions `inbound:"h2-flow,omitempty"`
	H2Params          *xhttp.H2Params            `inbound:"h2-params,omitempty"`
}

func (o XHTTPConfig) Build() LC.XHTTPConfig {
	return LC.XHTTPConfig{
		Path:                 o.Path,
		Host:                 o.Host,
		Mode:                 o.Mode,
		NoSSEHeader:          o.NoSSEHeader,
		XPaddingBytes:        o.XPaddingBytes,
		XPaddingObfsMode:     o.XPaddingObfsMode,
		XPaddingKey:          o.XPaddingKey,
		XPaddingHeader:       o.XPaddingHeader,
		XPaddingPlacement:    o.XPaddingPlacement,
		XPaddingMethod:       o.XPaddingMethod,
		UplinkHTTPMethod:     o.UplinkHTTPMethod,
		SessionPlacement:     o.SessionPlacement,
		SessionKey:           o.SessionKey,
		SeqPlacement:         o.SeqPlacement,
		SeqKey:               o.SeqKey,
		UplinkDataPlacement:  o.UplinkDataPlacement,
		UplinkDataKey:        o.UplinkDataKey,
		UplinkChunkSize:      o.UplinkChunkSize,
		ScStreamUpServerSecs: o.ScStreamUpServerSecs,
		ScMaxBufferedPosts:   o.ScMaxBufferedPosts,
		ScMaxEachPostBytes:   o.ScMaxEachPostBytes,
		MuxKeepAliveSecs:     o.MuxKeepAliveSecs,
		MuxKeepAliveBytes:    o.MuxKeepAliveBytes,
		H2Flow:               o.H2Flow,
		H2Params:             o.H2Params,
	}
}

// XDriveConfig is the xdrive-config of a vless listener: the options of the
// proxy's xdrive-opts, and the TLS settings of the requests the listener makes
// to the storage service, which a proxy takes from its own tls fields.
type XDriveConfig struct {
	xdrive.Options    `inbound:",squash"`
	ServerName        string   `inbound:"servername,omitempty"`
	ALPN              []string `inbound:"alpn,omitempty"`
	ClientFingerprint string   `inbound:"client-fingerprint,omitempty"`
	SkipCertVerify    bool     `inbound:"skip-cert-verify,omitempty"`
	Fingerprint       string   `inbound:"fingerprint,omitempty"`
}

func (o XDriveConfig) Build() LC.XDriveConfig {
	return LC.XDriveConfig{
		Options:           o.Options,
		ServerName:        o.ServerName,
		ALPN:              o.ALPN,
		ClientFingerprint: o.ClientFingerprint,
		SkipCertVerify:    o.SkipCertVerify,
		Fingerprint:       o.Fingerprint,
	}
}

func (o VlessOption) Equal(config C.InboundConfig) bool {
	return optionToString(o) == optionToString(config)
}

type Vless struct {
	*Base
	config *VlessOption
	l      C.MultiAddrListener
	vs     LC.VlessServer
}

func NewVless(options *VlessOption) (*Vless, error) {
	base, err := NewBase(&options.BaseOption)
	if err != nil {
		return nil, err
	}
	users := make([]LC.VlessUser, len(options.Users))
	for i, v := range options.Users {
		users[i] = LC.VlessUser{
			Username: v.Username,
			UUID:     v.UUID,
			Flow:     v.Flow,
		}
	}
	return &Vless{
		Base:   base,
		config: options,
		vs: LC.VlessServer{
			Enable:          true,
			Listen:          base.RawAddress(),
			Users:           users,
			Decryption:      options.Decryption,
			WsPath:          options.WsPath,
			XHTTPConfig:     options.XHTTPConfig.Build(),
			XDriveConfig:    options.XDriveConfig.Build(),
			GrpcServiceName: options.GrpcServiceName,
			Certificate:     options.Certificate,
			PrivateKey:      options.PrivateKey,
			ClientAuthType:  options.ClientAuthType,
			ClientAuthCert:  options.ClientAuthCert,
			EchKey:          options.EchKey,
			AllowInsecure:   options.AllowInsecure,
			ShadowTLS:       options.ShadowTLS.Build(),
			ResTLS:          options.ResTLS.Build(),
			JLSConfig:       options.JLSConfig.Build(),
			RealityConfig:   options.RealityConfig.Build(),
			MuxOption:       options.MuxOption.Build(),
			FinalMask:       options.FinalMask,
		},
	}, nil
}

// Config implements constant.InboundListener
func (v *Vless) Config() C.InboundConfig {
	return v.config
}

// Address implements constant.InboundListener
func (v *Vless) Address() string {
	var addrList []string
	if v.l != nil {
		for _, addr := range v.l.AddrList() {
			addrList = append(addrList, addr.String())
		}
	}
	return strings.Join(addrList, ",")
}

// Listen implements constant.InboundListener
func (v *Vless) Listen(tunnel C.Tunnel) error {
	var err error
	v.l, err = sing_vless.New(v.vs, v.ListenConfig(), tunnel, v.Additions()...)
	if err != nil {
		return err
	}
	log.Infoln("Vless[%s] proxy listening at: %s", v.Name(), v.Address())
	return nil
}

// Close implements constant.InboundListener
func (v *Vless) Close() error {
	return v.l.Close()
}

var _ C.InboundListener = (*Vless)(nil)
