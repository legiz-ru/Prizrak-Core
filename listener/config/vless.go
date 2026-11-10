package config

import (
	"encoding/json"

	"github.com/metacubex/mihomo/listener/reality"
	"github.com/metacubex/mihomo/listener/sing"
	"github.com/metacubex/mihomo/transport/finalmask/option"
	"github.com/metacubex/mihomo/transport/xdrive"
	"github.com/metacubex/mihomo/transport/xhttp"
)

type VlessUser struct {
	Username string
	UUID     string
	Flow     string
}

type VlessServer struct {
	Enable          bool
	Listen          string
	Users           []VlessUser
	Decryption      string
	WsPath          string
	XHTTPConfig     XHTTPConfig
	XDriveConfig    XDriveConfig
	GrpcServiceName string
	Certificate     string
	PrivateKey      string
	ClientAuthType  string
	ClientAuthCert  string
	EchKey          string
	AllowInsecure   bool
	ShadowTLS       ShadowTLS      `yaml:"shadow-tls" json:"shadow-tls,omitempty"`
	ResTLS          ResTLS         `yaml:"res-tls" json:"res-tls,omitempty"`
	JLSConfig       JLSConfig      `yaml:"jls-config" json:"jls-config,omitempty"`
	RealityConfig   reality.Config `yaml:"reality-config" json:"reality-config,omitempty"`
	MuxOption       sing.MuxOption `yaml:"mux-option" json:"mux-option,omitempty"`
	FinalMask       option.Option  `yaml:"finalmask" json:"finalmask,omitempty"`
}

// XDriveConfig is the xdrive-config of a vless listener: the options of the
// transport and the TLS of its requests to the storage service.
type XDriveConfig struct {
	xdrive.Options
	ServerName        string
	ALPN              []string
	ClientFingerprint string
	SkipCertVerify    bool
	Fingerprint       string
}

type XHTTPConfig struct {
	Path                 string
	Host                 string
	Mode                 string
	XPaddingBytes        string
	XPaddingObfsMode     bool
	XPaddingKey          string
	XPaddingHeader       string
	XPaddingPlacement    string
	XPaddingMethod       string
	UplinkHTTPMethod     string
	SessionPlacement     string
	SessionKey           string
	SeqPlacement         string
	SeqKey               string
	UplinkDataPlacement  string
	UplinkDataKey        string
	UplinkChunkSize      string
	NoSSEHeader          bool
	ScStreamUpServerSecs string
	ScMaxBufferedPosts   string
	ScMaxEachPostBytes   string
	MuxKeepAliveSecs     string
	MuxKeepAliveBytes    string
	H2Flow               *xhttp.H2FlowServerOptions `json:"h2-flow,omitempty"`
	H2Params             *xhttp.H2Params            `json:"h2-params,omitempty"`
}

func (t VlessServer) String() string {
	b, _ := json.Marshal(t)
	return string(b)
}
