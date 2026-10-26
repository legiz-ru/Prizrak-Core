// Package fragment is the "fragment" finalmask of Xray-core: it cuts the
// first writes of a TCP stream into pieces. The cutting itself is done by
// transport/fragment, which the freedom outbound uses as well.
package fragment

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/metacubex/mihomo/transport/finalmask"
	"github.com/metacubex/mihomo/transport/fragment"
)

// Option is the mask's settings as written in the config.
type Option struct {
	// Packets: "tlshello" splits the first TLS ClientHello into TLS records,
	// "" splits every write into TCP segments, "N-M" splits writes N to M.
	Packets string `proxy:"packets,omitempty"`
	// Length and Delay (milliseconds) are the [min, max) ranges for every
	// piece; Lengths and Delays give piece i its own range instead, the last
	// entry serving every later piece.
	Length   finalmask.Range   `proxy:"length,omitempty"`
	Delay    finalmask.Range   `proxy:"delay,omitempty"`
	Lengths  []finalmask.Range `proxy:"lengths,omitempty"`
	Delays   []finalmask.Range `proxy:"delays,omitempty"`
	MaxSplit finalmask.Range   `proxy:"max-split,omitempty"`
	// Interval is Xray's freedom spelling of Delay, taken when Delay is unset.
	Interval finalmask.Range `proxy:"interval,omitempty"`
}

type Mask struct {
	cfg *fragment.Config
}

func New(o Option) (*Mask, error) {
	cfg := &fragment.Config{FallbackDelay: fragment.DefaultFallbackDelay}
	switch strings.ToLower(strings.TrimSpace(o.Packets)) {
	case "tlshello":
		cfg.PacketsFrom, cfg.PacketsTo = 0, 1
	case "":
	default:
		from, to, err := finalmask.ParseRange(o.Packets)
		if err != nil {
			return nil, fmt.Errorf("fragment packets: %w", err)
		}
		if from <= 0 || to <= 0 {
			return nil, errors.New("fragment packets: the first packet is 1, not 0")
		}
		if from > to {
			from, to = to, from
		}
		cfg.PacketsFrom, cfg.PacketsTo = uint64(from), uint64(to)
	}

	lengths := o.Lengths
	if len(lengths) == 0 {
		lengths = []finalmask.Range{o.Length}
	}
	for _, r := range lengths {
		lo, hi, err := bounds(r)
		if err != nil {
			return nil, fmt.Errorf("fragment lengths: %w", err)
		}
		cfg.Lengths = append(cfg.Lengths, [2]uint64{lo, hi})
	}
	if cfg.Lengths[len(cfg.Lengths)-1][0] == 0 {
		return nil, errors.New("fragment length: the last lengths entry can't start at 0")
	}

	delay := o.Delay
	if delay.IsZero() {
		delay = o.Interval
	}
	delays := o.Delays
	if len(delays) == 0 {
		delays = []finalmask.Range{delay}
	}
	for _, r := range delays {
		lo, hi, err := bounds(r)
		if err != nil {
			return nil, fmt.Errorf("fragment delays: %w", err)
		}
		cfg.Delays = append(cfg.Delays, [2]uint64{lo, hi})
	}

	lo, hi, err := bounds(o.MaxSplit)
	if err != nil {
		return nil, fmt.Errorf("fragment max-split: %w", err)
	}
	cfg.MaxSplitMin, cfg.MaxSplitMax = lo, hi
	return &Mask{cfg: cfg}, nil
}

func bounds(r finalmask.Range) (uint64, uint64, error) {
	if r.From < 0 || r.To < 0 {
		return 0, 0, fmt.Errorf("%s can't be negative", r)
	}
	lo, hi := uint64(r.From), uint64(r.To)
	if lo > hi {
		lo, hi = hi, lo
	}
	return lo, hi, nil
}

func (m *Mask) Config() *fragment.Config { return m.cfg }

func (m *Mask) WrapConnClient(_ context.Context, conn net.Conn, _ *finalmask.Destination, _ *finalmask.Dialer) (net.Conn, error) {
	return &maskConn{Conn: fragment.NewConn(conn, m.cfg), raw: conn}, nil
}

// WrapConnServer fragments the server's writes the same way, as Xray does.
func (m *Mask) WrapConnServer(conn net.Conn) (net.Conn, error) {
	return &maskConn{Conn: fragment.NewConn(conn, m.cfg), raw: conn}, nil
}

type maskConn struct {
	*fragment.Conn
	raw net.Conn
}

func (c *maskConn) MaskConn() {}

func (c *maskConn) RawConn() net.Conn { return c.raw }

func (c *maskConn) Splice() bool { return c.Conn.WriterReplaceable() }

func (c *maskConn) CloseWrite() error {
	if cw, ok := c.raw.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}
