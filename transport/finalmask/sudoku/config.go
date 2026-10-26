// Package sudoku is the "sudoku" finalmask of Xray-core: a pure appearance
// transform of the bytes on the wire, with no handshake of its own. On TCP
// the client's writes use the classic encoding and the server's the packed
// one; UDP datagrams use the classic one.
package sudoku

import (
	"context"
	"net"

	"github.com/metacubex/mihomo/transport/finalmask"
)

// Config is the mask's settings, as written in the config.
type Config struct {
	Password string `proxy:"password,omitempty"`
	// ASCII: "prefer_entropy" (the default, also "entropy") or
	// "prefer_ascii" ("ascii").
	ASCII string `proxy:"ascii,omitempty"`
	// CustomTable is a bit layout of 8 letters: 2 x, 2 p, 4 v (entropy mode
	// only); CustomTables rotates several.
	CustomTable  string   `proxy:"custom-table,omitempty"`
	CustomTables []string `proxy:"custom-tables,omitempty"`
	// PaddingMin..PaddingMax is the chance in percent of a padding byte.
	PaddingMin uint32 `proxy:"padding-min,omitempty"`
	PaddingMax uint32 `proxy:"padding-max,omitempty"`
}

// New checks the config by building its tables.
func New(c Config) (*Config, error) {
	if _, err := getTables(&c); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Config) WrapConnClient(_ context.Context, conn net.Conn, _ *finalmask.Destination, _ *finalmask.Dialer) (net.Conn, error) {
	return newPackedDirectionalConn(conn, c, true)
}

func (c *Config) WrapConnServer(conn net.Conn) (net.Conn, error) {
	return newPackedDirectionalConn(conn, c, false)
}

func newPackedDirectionalConn(raw net.Conn, config *Config, readPacked bool) (net.Conn, error) {
	pureReader, pureWriter, err := newPureReaderWriter(raw, config)
	if err != nil {
		return nil, err
	}
	packedReader, packedWriter, err := newPackedReaderWriter(raw, config)
	if err != nil {
		return nil, err
	}

	reader, writer := pureReader, pureWriter
	if readPacked {
		reader = packedReader
	} else {
		writer = packedWriter
	}

	return newWrappedConn(raw, reader, writer), nil
}

func (c *Config) WrapPacketConnClient(_ context.Context, conn net.PacketConn, _ *finalmask.Destination, _ *finalmask.Dialer) (net.PacketConn, error) {
	return NewUDPConn(conn, c)
}

func (c *Config) WrapPacketConnServer(conn net.PacketConn) (net.PacketConn, error) {
	return NewUDPConn(conn, c)
}
