package xdns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/metacubex/mihomo/transport/finalmask"
)

// DomainConfig is one zone of the tunnel.
type DomainConfig struct {
	Name       string
	LenLimit   int      // longest query name, 255 by default
	LabelLimit int      // longest label, 63 by default
	Types      []uint16 // query types, TXT by default on the client
	EDNS0      uint16   // EDNS0 payload size to advertise, 0 for none
}

// Config is the built mask.
type Config struct {
	Domains   []DomainConfig
	Resolvers []ResolverConfig
	ExtraPoll int32 // extra polls after every write, 0 to 3
}

// Option is the mask's settings as written in the config.
type Option struct {
	Domains   []DomainOption   `proxy:"domains"`
	Resolvers []ResolverOption `proxy:"resolvers"`
	ExtraPoll int              `proxy:"extra-poll,omitempty"`
}

type DomainOption struct {
	Names      []string `proxy:"names"`
	LenLimit   int      `proxy:"len-limit,omitempty"`
	LabelLimit int      `proxy:"label-limit,omitempty"`
	// Types are DNS record types by number: 1 (A), 5 (CNAME), 16 (TXT), 28
	// (AAAA); TXT by default.
	Types []int `proxy:"types,omitempty"`
	EDNS0 int   `proxy:"edns0,omitempty"`
}

// ResolverOption lists resolver addresses: "udp://1.1.1.1:53",
// "tcp://1.1.1.1", or "1.1.1.1" for UDP on port 53.
type ResolverOption struct {
	Addrs []string `proxy:"addrs"`
}

func New(o Option) (*Config, error) {
	c := &Config{}
	for _, d := range o.Domains {
		lenLimit := d.LenLimit
		if lenLimit == 0 {
			lenLimit = 255
		}
		labelLimit := d.LabelLimit
		if labelLimit == 0 {
			labelLimit = 63
		}
		types := make([]uint16, 0, len(d.Types))
		for _, t := range d.Types {
			if t < 0 || t > 65535 {
				return nil, fmt.Errorf("xdns: invalid type %d", t)
			}
			types = append(types, uint16(t))
		}
		if d.EDNS0 < 0 || d.EDNS0 > 65535 {
			return nil, fmt.Errorf("xdns: invalid edns0 %d", d.EDNS0)
		}
		for _, name := range d.Names {
			checkTypes := types
			if len(checkTypes) == 0 {
				checkTypes = []uint16{TypeA, TypeCNAME, TypeTXT, TypeAAAA}
			}
			if _, err := NewDomain(name, lenLimit, labelLimit, checkTypes, uint16(d.EDNS0)); err != nil {
				return nil, fmt.Errorf("xdns: %w", err)
			}
			c.Domains = append(c.Domains, DomainConfig{
				Name:       name,
				LenLimit:   lenLimit,
				LabelLimit: labelLimit,
				Types:      types,
				EDNS0:      uint16(d.EDNS0),
			})
		}
	}
	if len(c.Domains) == 0 {
		return nil, errors.New("xdns: domains are required")
	}
	for _, r := range o.Resolvers {
		for _, addr := range r.Addrs {
			resolver, err := ParseResolver(addr)
			if err != nil {
				return nil, err
			}
			c.Resolvers = append(c.Resolvers, resolver)
		}
	}
	if len(c.Resolvers) == 0 {
		return nil, errors.New("xdns: resolvers are required")
	}
	if o.ExtraPoll < 0 || o.ExtraPoll > 3 {
		return nil, errors.New("xdns: extra-poll must be between 0 and 3")
	}
	c.ExtraPoll = int32(o.ExtraPoll)
	return c, nil
}

// ParseResolver reads a resolver address, see ResolverOption.
func ParseResolver(addr string) (ResolverConfig, error) {
	var u *url.URL
	var err error
	if !strings.Contains(addr, "://") {
		u, err = url.Parse("udp://" + addr)
	} else {
		u, err = url.Parse(addr)
	}
	if err != nil {
		return ResolverConfig{}, fmt.Errorf("xdns: resolver %q: %w", addr, err)
	}
	switch u.Scheme {
	case "tcp", "udp":
	default:
		return ResolverConfig{}, fmt.Errorf("xdns: resolver %q: unknown scheme %q, want udp or tcp", addr, u.Scheme)
	}
	host, port := u.Hostname(), u.Port()
	// An address without a host, like ":53", reaches the resolver on this
	// machine; one with neither host nor port names nothing.
	if host == "" && port == "" {
		return ResolverConfig{}, fmt.Errorf("xdns: resolver address %q is empty", addr)
	}
	if port == "" {
		port = "53"
	}
	if p, err := strconv.ParseUint(port, 10, 16); err != nil || p == 0 {
		return ResolverConfig{}, fmt.Errorf("xdns: resolver address %q has no valid port", addr)
	}
	return ResolverConfig{Type: u.Scheme, Addr: net.JoinHostPort(host, port)}, nil
}

// HandleDial marks XDNS as a mask that reaches the network only through its
// own resolvers, so the chain does not open a base socket for it.
func (c *Config) HandleDial() {}

func (c *Config) WrapPacketConnClient(ctx context.Context, _ net.PacketConn, _ *finalmask.Destination, dialer *finalmask.Dialer) (net.PacketConn, error) {
	return NewClient(ctx, c, dialer)
}

func (c *Config) WrapPacketConnServer(conn net.PacketConn) (net.PacketConn, error) {
	return NewServer(c, conn)
}
