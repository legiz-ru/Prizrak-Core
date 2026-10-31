package outbound

import (
	"errors"
	"net"
	"sync"

	N "github.com/metacubex/mihomo/common/net"
)

// errIdleSession closes a session C.IdleCloser found unused.
var errIdleSession = errors.New("idle session closed to save power")

// countedConn calls release once, when it is closed: how an adapter keeps the
// number of connections open through a shared session (see Hysteria2.CloseIdle).
type countedConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *countedConn) Close() error {
	c.once.Do(c.release)
	return c.Conn.Close()
}

func (c *countedConn) Upstream() any {
	return c.Conn
}

func (c *countedConn) ReaderReplaceable() bool {
	return true
}

func (c *countedConn) WriterReplaceable() bool {
	return true
}

type countedPacketConn struct {
	net.PacketConn
	once    sync.Once
	release func()
}

func (c *countedPacketConn) Close() error {
	c.once.Do(c.release)
	return c.PacketConn.Close()
}

func (c *countedPacketConn) Upstream() any {
	return c.PacketConn
}

var (
	_ N.ReaderWithUpstream = (*countedConn)(nil)
	_ N.WriterWithUpstream = (*countedConn)(nil)
)
