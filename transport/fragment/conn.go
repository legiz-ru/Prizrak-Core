package fragment

import (
	"context"
	"net"
	"time"

	"github.com/metacubex/randv2"
)

// Conn fragments the first writes of a connection as configured and then
// gets out of the way: once it is done it reports itself replaceable, so the
// relay writes to the inner connection directly.
type Conn struct {
	net.Conn
	cfg    *Config
	tcp    *net.TCPConn
	ctx    context.Context
	cancel context.CancelFunc

	count   uint64
	pending []byte // a ClientHello record that came in more than one write
	done    bool
}

func NewConn(conn net.Conn, cfg *Config) *Conn {
	ctx, cancel := context.WithCancel(context.Background())
	return &Conn{Conn: conn, cfg: cfg, tcp: unwrapTCP(conn), ctx: ctx, cancel: cancel}
}

func (c *Conn) Write(b []byte) (int, error) {
	if c.done {
		return c.Conn.Write(b)
	}
	if c.pending != nil {
		c.pending = append(c.pending, b...)
		if l := handshakeRecordLen(c.pending); len(c.pending) < l || (l == 0 && recordStart(c.pending)) {
			return len(b), nil
		}
		data := c.pending
		c.pending = nil
		if err := c.writeFirst(data); err != nil {
			return 0, err
		}
		return len(b), nil
	}
	if len(b) == 0 {
		return 0, nil
	}
	c.count++
	if c.count == 1 {
		// The ClientHello may come in pieces (a large post-quantum one from a
		// TUN stack does); hold it until the record is complete, as cutting a
		// part would leave the rest without its record header.
		if l := handshakeRecordLen(b); l > len(b) || (l == 0 && recordStart(b)) {
			c.pending = append(make([]byte, 0, l), b...)
			return len(b), nil
		}
		if err := c.writeFirst(b); err != nil {
			return 0, err
		}
		return len(b), nil
	}
	return c.writeNext(b)
}

func (c *Conn) writeFirst(b []byte) error {
	if c.cfg.TLSHello() {
		c.done = true
		if handshakeRecordLen(b) == 0 {
			_, err := c.Conn.Write(b)
			return err
		}
		return c.writeHello(b)
	}
	_, err := c.writeNext(b)
	return err
}

// writeNext handles every write in the TCP segmentation modes.
func (c *Conn) writeNext(b []byte) (int, error) {
	cfg := c.cfg
	if cfg.PacketsFrom != 0 && (c.count < cfg.PacketsFrom || c.count > cfg.PacketsTo) {
		if c.count > cfg.PacketsTo {
			c.done = true
		}
		return c.Conn.Write(b)
	}
	if cfg.PacketsTo != 0 && c.count == cfg.PacketsTo {
		c.done = true
	}
	var cuts []int
	if cfg.SplitSNI {
		cuts = sniCuts(b)
	} else {
		cuts = c.lengthCuts(len(b))
	}
	if len(cuts) == 0 {
		return c.Conn.Write(b)
	}
	c.noDelay()
	from := 0
	for i, to := range append(cuts, len(b)) {
		if i > 0 {
			c.pause(i - 1)
		}
		n, err := c.Conn.Write(b[from:to])
		from += n
		if err != nil {
			return from, err
		}
	}
	return len(b), nil
}

// writeHello rewrites the first ClientHello record into several records, as
// Xray's "tlshello": one write with an interval of 0, one TCP segment per
// record otherwise.
func (c *Conn) writeHello(b []byte) error {
	recordLen := handshakeRecordLen(b)
	payload := b[recordHeaderLen:recordLen]
	var cuts []int
	if c.cfg.SplitSNI {
		for _, cut := range sniCuts(b) {
			cuts = append(cuts, cut-recordHeaderLen)
		}
	} else {
		cuts = c.lengthCuts(len(payload))
	}
	if len(cuts) == 0 {
		_, err := c.Conn.Write(b)
		return err
	}
	cuts = append(cuts, len(payload))
	separate := c.cfg.separate()
	if separate {
		c.noDelay()
	}
	var out []byte
	from := 0
	for i, to := range cuts {
		record := make([]byte, 0, recordHeaderLen+to-from)
		record = append(record, b[:3]...)
		record = append(record, byte((to-from)>>8), byte(to-from))
		record = append(record, payload[from:to]...)
		from = to
		if !separate {
			out = append(out, record...)
			continue
		}
		if i > 0 {
			c.pause(i - 1)
		}
		if _, err := c.Conn.Write(record); err != nil {
			return err
		}
	}
	if len(b) > recordLen {
		out = append(out, b[recordLen:]...)
	}
	if len(out) > 0 {
		if separate {
			c.pause(len(cuts) - 1)
		}
		_, err := c.Conn.Write(out)
		return err
	}
	return nil
}

// lengthCuts cuts n bytes into pieces of LengthMin..LengthMax, at most
// MaxSplit pieces, like Xray's FragmentWriter.
func (c *Conn) lengthCuts(n int) []int {
	cfg := c.cfg
	maxSplit := randBetween(cfg.MaxSplitMin, cfg.MaxSplitMax)
	var cuts []int
	var pieces uint64
	for from := 0; ; {
		lengthMin, lengthMax := cfg.lengthRange(int(pieces))
		to := from + int(randBetween(lengthMin, lengthMax))
		pieces++
		if to >= n || (maxSplit > 0 && pieces >= maxSplit) {
			return cuts
		}
		cuts = append(cuts, to)
		from = to
	}
}

// pause waits after piece i: for its ACK, or for a random interval.
func (c *Conn) pause(i int) {
	if c.cfg.WaitAck {
		waitAck(c.ctx, c.tcp, c.cfg.FallbackDelay)
		return
	}
	delayMin, delayMax := c.cfg.delayRange(i)
	if delayMax == 0 {
		return
	}
	if d := randBetween(delayMin, delayMax); d > 0 {
		sleep(c.ctx, time.Duration(d)*time.Millisecond)
	}
}

func (c *Conn) noDelay() {
	if c.tcp != nil {
		_ = c.tcp.SetNoDelay(true)
	}
}

func (c *Conn) Close() error {
	c.cancel()
	return c.Conn.Close()
}

func (c *Conn) Upstream() any { return c.Conn }

func (c *Conn) ReaderReplaceable() bool { return true }

func (c *Conn) WriterReplaceable() bool { return c.done && c.pending == nil }

// randBetween returns a value in [from, to), or from when the range is empty,
// the same as Xray's crypto.RandBetween.
func randBetween(from, to uint64) uint64 {
	if to <= from+1 {
		return from
	}
	return from + randv2.Uint64N(to-from)
}

func sleep(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
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
