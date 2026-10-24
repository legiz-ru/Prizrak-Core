// Package sockopt applies per-outbound TCP socket options, modelled on the
// sockopt block of Xray-core's streamSettings (tcpcongestion, tcpUserTimeout,
// tcpKeepAliveIdle, tcpKeepAliveInterval and customSockopt).
//
// An option the platform or the kernel does not support is skipped with a
// warning instead of failing the connection: a missing congestion control
// module (bbr on many Android kernels) should not take the outbound down.
package sockopt

import (
	"context"
	"fmt"
	"net"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/metacubex/mihomo/log"
)

const levelTCP = 6 // IPPROTO_TCP, the default level of a custom option as in Xray

type Custom struct {
	System  string // runtime.GOOS the option applies to; empty means every system, "linux" also matches android
	Network string // network prefix the option applies to ("tcp", "tcp4", ...); empty means every network
	Level   int
	Opt     int
	Int     bool // the value is an int, otherwise a string
	IntVal  int
	StrVal  string
	display string
}

type Options struct {
	Name string // outbound name for log messages

	TCPCongestion     string
	TCPUserTimeout    int // milliseconds, 0 leaves the system default
	KeepAliveIdle     int // seconds, 0 leaves the default, negative disables keep-alive
	KeepAliveInterval int // seconds, 0 leaves the default, negative disables keep-alive
	Custom            []Custom

	warned sync.Map
}

// ParseCustom parses an Xray-style custom option. level and opt accept
// decimal or 0x-prefixed numbers; typ is "int" or "str".
func ParseCustom(system, network, level, opt, typ, value string) (Custom, error) {
	c := Custom{System: strings.ToLower(system), Network: strings.ToLower(network), Level: levelTCP}
	if opt == "" {
		return c, fmt.Errorf("custom-sockopt: opt is empty")
	}
	o, err := strconv.ParseInt(opt, 0, 32)
	if err != nil {
		return c, fmt.Errorf("custom-sockopt: invalid opt %q: %w", opt, err)
	}
	c.Opt = int(o)
	if level != "" {
		l, err := strconv.ParseInt(level, 0, 32)
		if err != nil {
			return c, fmt.Errorf("custom-sockopt: invalid level %q: %w", level, err)
		}
		c.Level = int(l)
	}
	switch strings.ToLower(typ) {
	case "int", "":
		v, err := strconv.ParseInt(value, 0, 32)
		if err != nil {
			return c, fmt.Errorf("custom-sockopt: invalid int value %q: %w", value, err)
		}
		c.Int, c.IntVal = true, int(v)
	case "str", "string":
		c.StrVal = value
	default:
		return c, fmt.Errorf("custom-sockopt: unknown type %q, want int or str", typ)
	}
	c.display = fmt.Sprintf("level %d opt %d", c.Level, c.Opt)
	return c, nil
}

func (c *Custom) matches(network string) bool {
	if c.System != "" && c.System != runtime.GOOS && !(c.System == "linux" && runtime.GOOS == "android") {
		return false
	}
	return strings.HasPrefix(network, c.Network)
}

// Control sets the options that have to be in place before connect. It is
// meant for net.Dialer.ControlContext and never fails the dial.
func (o *Options) Control(_ context.Context, network, _ string, c syscall.RawConn) error {
	if !strings.HasPrefix(network, "tcp") {
		return nil
	}
	_ = c.Control(func(fd uintptr) {
		o.apply(fd, network, true)
	})
	return nil
}

// AfterDial applies keep-alive, which Go sets on the connection after connect
// and would override from Control, and repeats the custom options, so one Go
// also sets after connect (TCP_NODELAY) keeps the configured value.
func (o *Options) AfterDial(conn net.Conn) {
	tcp := unwrapTCP(conn)
	if tcp == nil {
		return
	}
	if o.KeepAliveIdle != 0 || o.KeepAliveInterval != 0 {
		if err := setKeepAlive(tcp, o.KeepAliveIdle, o.KeepAliveInterval); err != nil {
			o.warn("keep-alive", err)
		}
	}
	if len(o.Custom) > 0 {
		if raw, err := tcp.SyscallConn(); err == nil {
			_ = raw.Control(func(fd uintptr) {
				o.apply(fd, tcp.LocalAddr().Network(), false)
			})
		}
	}
}

func (o *Options) apply(fd uintptr, network string, beforeConnect bool) {
	if beforeConnect {
		if o.TCPCongestion != "" {
			if err := setCongestion(fd, o.TCPCongestion); err != nil {
				o.warn("tcp-congestion "+o.TCPCongestion, err)
			}
		}
		if o.TCPUserTimeout > 0 {
			if err := setUserTimeout(fd, o.TCPUserTimeout); err != nil {
				o.warn("tcp-user-timeout", err)
			}
		}
	}
	for i := range o.Custom {
		c := &o.Custom[i]
		if !c.matches(network) {
			continue
		}
		var err error
		if c.Int {
			err = setInt(fd, c.Level, c.Opt, c.IntVal)
		} else {
			err = setString(fd, c.Level, c.Opt, c.StrVal)
		}
		if err != nil {
			o.warn("custom-sockopt "+c.display, err)
		}
	}
}

// warn logs a failed option once per outbound and option, later failures go to debug.
func (o *Options) warn(what string, err error) {
	if _, seen := o.warned.LoadOrStore(what, struct{}{}); seen {
		log.Debugln("[Sockopt] [%s] %s skipped: %v", o.Name, what, err)
		return
	}
	log.Warnln("[Sockopt] [%s] %s is not applied, skipping it: %v", o.Name, what, err)
}

func unwrapTCP(conn net.Conn) *net.TCPConn {
	for i := 0; i < 8 && conn != nil; i++ {
		if tcp, ok := conn.(*net.TCPConn); ok {
			return tcp
		}
		u, ok := conn.(interface{ Upstream() any })
		if !ok {
			return nil
		}
		conn, _ = u.Upstream().(net.Conn)
	}
	return nil
}
