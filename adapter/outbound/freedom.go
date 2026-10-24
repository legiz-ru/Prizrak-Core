package outbound

import (
	"context"
	"fmt"
	"net"

	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/loopback"
	"github.com/metacubex/mihomo/component/resolver"
	"github.com/metacubex/mihomo/component/sockopt"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/fragment"
)

// Freedom is DIRECT with the fragment and sockopt settings of Xray-core's
// freedom outbound. UDP goes out as with DIRECT.
type Freedom struct {
	*Direct
	fragment *fragment.Config
	sockopt  *sockopt.Options
}

type FreedomOption struct {
	BasicOption
	Name     string                 `proxy:"name"`
	Fragment *FreedomFragmentOption `proxy:"fragment,omitempty"`
	Sockopt  *FreedomSockoptOption  `proxy:"sockopt,omitempty"`
}

type FreedomFragmentOption struct {
	Packets       string `proxy:"packets,omitempty"`
	Length        string `proxy:"length,omitempty"`
	Interval      string `proxy:"interval,omitempty"`
	MaxSplit      string `proxy:"max-split,omitempty"`
	Split         string `proxy:"split,omitempty"`
	Wait          string `proxy:"wait,omitempty"`
	FallbackDelay int    `proxy:"fallback-delay,omitempty"`
}

type FreedomSockoptOption struct {
	TCPCongestion        string                 `proxy:"tcp-congestion,omitempty"`
	TCPUserTimeout       int                    `proxy:"tcp-user-timeout,omitempty"`
	TCPKeepAliveIdle     int                    `proxy:"tcp-keep-alive-idle,omitempty"`
	TCPKeepAliveInterval int                    `proxy:"tcp-keep-alive-interval,omitempty"`
	CustomSockopt        []FreedomCustomSockopt `proxy:"custom-sockopt,omitempty"`
}

type FreedomCustomSockopt struct {
	System  string `proxy:"system,omitempty"`
	Network string `proxy:"network,omitempty"`
	Level   string `proxy:"level,omitempty"`
	Opt     string `proxy:"opt"`
	Type    string `proxy:"type,omitempty"`
	Value   string `proxy:"value"`
}

// DialContext implements C.ProxyAdapter
func (f *Freedom) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	if err := f.loopBack.CheckConn(metadata); err != nil {
		return nil, err
	}
	opts := f.DialOptions()
	opts = append(opts, dialer.WithResolver(resolver.DirectHostResolver))
	if f.sockopt != nil {
		opts = append(opts, dialer.WithNetDialer(&net.Dialer{ControlContext: f.sockopt.Control}))
	}
	c, err := dialer.DialContext(ctx, "tcp", metadata.RemoteAddress(), opts...)
	if err != nil {
		return nil, err
	}
	if f.sockopt != nil {
		f.sockopt.AfterDial(c)
	}
	if f.fragment != nil {
		c = fragment.NewConn(c, f.fragment)
	}
	return f.loopBack.NewConn(NewConn(c, f)), nil
}

// ListenPacketContext implements C.ProxyAdapter
func (f *Freedom) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (C.PacketConn, error) {
	if err := f.loopBack.CheckPacketConn(metadata); err != nil {
		return nil, err
	}
	if err := f.ResolveUDP(ctx, metadata); err != nil {
		return nil, err
	}
	pc, err := dialer.NewDialer(f.DialOptions()...).ListenPacket(ctx, "udp", "", metadata.AddrPort())
	if err != nil {
		return nil, err
	}
	return f.loopBack.NewPacketConn(NewPacketConn(pc, f)), nil
}

func NewFreedom(option FreedomOption) (*Freedom, error) {
	f := &Freedom{
		Direct: &Direct{
			Base: NewBase(BaseOption{
				Name:         option.Name,
				Type:         C.Freedom,
				ProviderName: option.ProviderName,
				UDP:          true,
				TFO:          option.TFO,
				MPTCP:        option.MPTCP,
				Interface:    option.Interface,
				RoutingMark:  option.RoutingMark,
				Prefer:       option.IPVersion,
			}),
			loopBack: loopback.NewDetector(),
		},
	}
	if o := option.Fragment; o != nil {
		cfg, err := fragment.NewConfig(fragment.Option{
			Packets:       o.Packets,
			Length:        o.Length,
			Interval:      o.Interval,
			MaxSplit:      o.MaxSplit,
			Split:         o.Split,
			Wait:          o.Wait,
			FallbackDelay: o.FallbackDelay,
		})
		if err != nil {
			return nil, fmt.Errorf("%s: %w", option.Name, err)
		}
		f.fragment = cfg
	}
	if o := option.Sockopt; o != nil {
		so := &sockopt.Options{
			Name:              option.Name,
			TCPCongestion:     o.TCPCongestion,
			TCPUserTimeout:    o.TCPUserTimeout,
			KeepAliveIdle:     o.TCPKeepAliveIdle,
			KeepAliveInterval: o.TCPKeepAliveInterval,
		}
		for _, c := range o.CustomSockopt {
			custom, err := sockopt.ParseCustom(c.System, c.Network, c.Level, c.Opt, c.Type, c.Value)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", option.Name, err)
			}
			so.Custom = append(so.Custom, custom)
		}
		f.sockopt = so
	}
	return f, nil
}
