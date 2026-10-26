package custom

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/transport/finalmask"
)

var errHeaderAuth = errors.New("header auth failed")

func (c *TCPConfig) WrapConnClient(_ context.Context, conn net.Conn, _ *finalmask.Destination, _ *finalmask.Dialer) (net.Conn, error) {
	return NewConnClientTCP(c, conn)
}

func (c *TCPConfig) WrapConnServer(conn net.Conn) (net.Conn, error) {
	return NewConnServerTCP(c, conn)
}

type tcpCustomClient struct {
	clients []*TCPSequence
	servers []*TCPSequence
	state   *stateStore
}

// tcpCustomClientConn runs the exchange on the first Write and lets the
// stream through once the server answered as scripted.
type tcpCustomClientConn struct {
	net.Conn
	header *tcpCustomClient

	auth     bool
	finished atomic.Bool
	wg       sync.WaitGroup
	once     sync.Once
}

func NewConnClientTCP(c *TCPConfig, raw net.Conn) (net.Conn, error) {
	conn := &tcpCustomClientConn{
		Conn: raw,
		header: &tcpCustomClient{
			clients: c.Clients,
			servers: c.Servers,
			state:   newStateStore(5 * time.Second),
		},
	}

	conn.wg.Add(1)

	return conn, nil
}

func (c *tcpCustomClientConn) CloseWrite() error {
	if _, err := c.Write(nil); err != nil {
		return err
	}
	if closeWriter, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return closeWriter.CloseWrite()
	}
	return nil
}

func (c *tcpCustomClientConn) MaskConn() {}

func (c *tcpCustomClientConn) RawConn() net.Conn { return c.Conn }

// Splice is true: after the exchange the stream is the raw one.
func (c *tcpCustomClientConn) Splice() bool { return true }

func (c *tcpCustomClientConn) Upstream() any { return c.Conn }

// Once the exchange went through, the relay may copy to and from the raw
// connection directly.
func (c *tcpCustomClientConn) ReaderReplaceable() bool { return c.finished.Load() && c.auth }

func (c *tcpCustomClientConn) WriterReplaceable() bool { return c.finished.Load() && c.auth }

func (c *tcpCustomClientConn) Read(p []byte) (n int, err error) {
	c.wg.Wait()

	if !c.auth {
		return 0, errHeaderAuth
	}

	return c.Conn.Read(p)
}

func (c *tcpCustomClientConn) Write(p []byte) (n int, err error) {
	c.once.Do(func() {
		defer c.wg.Done()
		defer c.finished.Store(true)
		ctx := newEvalContextWithAddrs(c.LocalAddr(), c.RemoteAddr())
		if vars, ok := c.header.state.get(tcpStateKey(c.LocalAddr(), c.RemoteAddr())); ok {
			ctx.vars = cloneVars(vars)
		}
		j := 0
		for i := range c.header.clients {
			if !writeSequenceWithContext(c.Conn, c.header.clients[i], ctx) {
				return
			}

			if j < len(c.header.servers) {
				if !readSequenceWithContext(c.Conn, c.header.servers[j], ctx) {
					return
				}
				j++
			}
		}

		for j < len(c.header.servers) {
			if !readSequenceWithContext(c.Conn, c.header.servers[j], ctx) {
				return
			}
			j++
		}

		c.header.state.set(tcpStateKey(c.LocalAddr(), c.RemoteAddr()), ctx.vars)
		c.auth = true
	})

	c.wg.Wait()

	if !c.auth {
		return 0, errHeaderAuth
	}

	return c.Conn.Write(p)
}

type tcpCustomServer struct {
	clients []*TCPSequence
	servers []*TCPSequence
	errors  []*TCPSequence
	state   *stateStore
}

type tcpCustomServerConn struct {
	net.Conn
	header *tcpCustomServer

	auth bool
	wg   sync.WaitGroup
	once sync.Once
}

func NewConnServerTCP(c *TCPConfig, raw net.Conn) (net.Conn, error) {
	conn := &tcpCustomServerConn{
		Conn: raw,
		header: &tcpCustomServer{
			clients: c.Clients,
			servers: c.Servers,
			errors:  c.Errors,
			state:   newStateStore(5 * time.Second),
		},
	}

	conn.wg.Add(1)

	return conn, nil
}

func (c *tcpCustomServerConn) CloseWrite() error {
	c.wg.Wait()
	if closeWriter, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return closeWriter.CloseWrite()
	}
	return nil
}

func (c *tcpCustomServerConn) MaskConn() {}

func (c *tcpCustomServerConn) RawConn() net.Conn { return c.Conn }

func (c *tcpCustomServerConn) Splice() bool { return true }

func (c *tcpCustomServerConn) Read(p []byte) (n int, err error) {
	c.once.Do(func() {
		defer c.wg.Done()
		ctx := newEvalContextWithAddrs(c.LocalAddr(), c.RemoteAddr())
		if vars, ok := c.header.state.get(tcpStateKey(c.LocalAddr(), c.RemoteAddr())); ok {
			ctx.vars = cloneVars(vars)
		}
		j := 0
		for i := range c.header.clients {
			if !readSequenceWithContext(c.Conn, c.header.clients[i], ctx) {
				if i < len(c.header.errors) {
					writeSequenceWithContext(c.Conn, c.header.errors[i], ctx)
				}
				return
			}

			if j < len(c.header.servers) {
				if !writeSequenceWithContext(c.Conn, c.header.servers[j], ctx) {
					return
				}
				j++
			}
		}

		for j < len(c.header.servers) {
			if !writeSequenceWithContext(c.Conn, c.header.servers[j], ctx) {
				return
			}
			j++
		}

		c.header.state.set(tcpStateKey(c.LocalAddr(), c.RemoteAddr()), ctx.vars)
		c.auth = true
	})

	c.wg.Wait()

	if !c.auth {
		return 0, errHeaderAuth
	}

	return c.Conn.Read(p)
}

func (c *tcpCustomServerConn) Write(p []byte) (n int, err error) {
	c.wg.Wait()

	if !c.auth {
		return 0, errHeaderAuth
	}

	return c.Conn.Write(p)
}

func readSequenceWithContext(r io.Reader, sequence *TCPSequence, ctx *evalContext) bool {
	for _, item := range sequence.Sequence {
		length, err := measureItem(item.Rand, item.Packet, item.Save, item.Var, item.Expr, sizeMapFromEvalContext(ctx))
		if err != nil {
			return false
		}
		buf := make([]byte, length)
		n, err := io.ReadFull(r, buf)
		if err != nil {
			return false
		}
		if n != length {
			return false
		}
		switch {
		case item.Rand > 0:
		case len(item.Packet) > 0:
			if !bytes.Equal(item.Packet, buf[:n]) {
				return false
			}
		case item.Var != "":
			saved, ok := ctx.vars[item.Var]
			if !ok || !bytes.Equal(saved, buf[:n]) {
				return false
			}
		case item.Expr != nil:
			evaluated, err := evaluateExpr(item.Expr, ctx)
			if err != nil {
				return false
			}
			expected, err := evaluated.asBytes()
			if err != nil || !bytes.Equal(expected, buf[:n]) {
				return false
			}
		}
		if item.Save != "" {
			ctx.vars[item.Save] = append([]byte(nil), buf[:n]...)
		}
	}
	return true
}

// writeSequenceWithContext writes the sequence, merging items into one write
// unless an item asks for a delay before it.
func writeSequenceWithContext(w io.Writer, sequence *TCPSequence, ctx *evalContext) bool {
	var merged []byte
	for _, item := range sequence.Sequence {
		if item.DelayMax > 0 {
			if len(merged) > 0 {
				_, err := w.Write(merged)
				if err != nil {
					return false
				}
				merged = nil
			}
			time.Sleep(time.Duration(finalmask.RandBetween(item.DelayMin, item.DelayMax)) * time.Millisecond)
		}
		evaluated, err := evaluateItem(item.Rand, item.RandMin, item.RandMax, item.Packet, item.Save, item.Var, item.Expr, ctx)
		if err != nil {
			return false
		}
		merged = append(merged, evaluated...)
	}
	if len(merged) > 0 {
		_, err := w.Write(merged)
		if err != nil {
			return false
		}
	}
	return true
}

func tcpStateKey(local, remote net.Addr) string {
	localKey := ""
	if local != nil {
		localKey = local.String()
	}
	remoteKey := ""
	if remote != nil {
		remoteKey = remote.String()
	}
	return localKey + "|" + remoteKey
}
