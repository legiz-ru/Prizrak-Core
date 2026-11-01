package xhttp

import (
	"errors"
	"io"
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/common/httputils"
)

type Conn struct {
	writer  io.WriteCloser
	reader  io.ReadCloser
	onClose func()
	httputils.NetAddr

	// deadlines
	deadline *time.Timer

	// muxKeepAlive and muxKeepAliveBytes are set on the server's packet-up
	// and stream-up downlinks, see MuxKeepAlive.
	muxKeepAlive      Range
	muxKeepAliveBytes Range
	lastWrite         atomic.Int64
}

func (c *Conn) Write(b []byte) (int, error) {
	n, err := c.writer.Write(b)
	if n > 0 && c.muxKeepAlive.Max > 0 {
		c.markWritten()
	}
	return n, err
}

// MuxKeepAlive reports how long, in seconds, this downlink may carry nothing
// before a Mux.Cool server pokes it with a KeepAlive frame. It is set only
// where the downlink is a long-lived response of its own, as in packet-up and
// stream-up, which is what CDN and reverse proxy idle timers cut; zero leaves
// the downlink alone.
func (c *Conn) MuxKeepAlive() (int32, int32) {
	return int32(c.muxKeepAlive.Min), int32(c.muxKeepAlive.Max)
}

// MuxKeepAliveBytes reports how much padding to put in each poke, so that
// they do not all leave at one telling size.
func (c *Conn) MuxKeepAliveBytes() (int32, int32) {
	return int32(c.muxKeepAliveBytes.Min), int32(c.muxKeepAliveBytes.Max)
}

// monotonicEpoch anchors downlink write times to the monotonic clock, so a
// wall-clock step cannot stretch or skip a KeepAlive.
var monotonicEpoch = time.Now()

func (c *Conn) markWritten() {
	c.lastWrite.Store(int64(time.Since(monotonicEpoch)))
}

// DownlinkIdle reports how long this downlink has carried nothing.
func (c *Conn) DownlinkIdle() time.Duration {
	return time.Since(monotonicEpoch) - time.Duration(c.lastWrite.Load())
}

func (c *Conn) Read(b []byte) (int, error) {
	return c.reader.Read(b)
}

func (c *Conn) Close() error {
	err := c.writer.Close()
	err2 := c.reader.Close()
	if c.onClose != nil {
		c.onClose()
	}
	return errors.Join(err, err2)
}

func (c *Conn) SetReadDeadline(t time.Time) error  { return c.SetDeadline(t) }
func (c *Conn) SetWriteDeadline(t time.Time) error { return c.SetDeadline(t) }

func (c *Conn) SetDeadline(t time.Time) error {
	if t.IsZero() {
		if c.deadline != nil {
			c.deadline.Stop()
			c.deadline = nil
		}
		return nil
	}
	d := time.Until(t)
	if c.deadline != nil {
		c.deadline.Reset(d)
		return nil
	}
	c.deadline = time.AfterFunc(d, func() {
		c.Close()
	})
	return nil
}
