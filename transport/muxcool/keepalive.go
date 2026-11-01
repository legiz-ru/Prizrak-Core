package muxcool

import (
	"crypto/rand"
	"time"

	randv2 "github.com/metacubex/randv2"
)

// KeepAliveConn is implemented by carriers whose downlink is an HTTP response
// that middleboxes cut once it carries nothing for a while, as the XHTTP
// server's packet-up and stream-up downlinks. It reports how long, in
// seconds, the downlink may stay silent, how much padding a poke carries and
// how long the downlink has been silent. Zero seconds leaves it alone.
type KeepAliveConn interface {
	MuxKeepAlive() (from, to int32)
	MuxKeepAliveBytes() (from, to int32)
	DownlinkIdle() time.Duration
}

// maxKeepAlivePadding keeps a KeepAlive frame and its padding small.
const maxKeepAlivePadding = 1024

func rollRange(from, to int32) int {
	if to < from {
		to = from
	}
	return int(from) + randv2.IntN(int(to-from+1))
}

// keepAlive sends the KeepAlive frame every client discards, so that a
// downlink whose sessions are all quiet is not taken for idle on the way. It
// pokes only a downlink that has fallen silent, and only a carrier that asks
// for it gets one, so others gain no pattern. It ends with the carrier; the
// carrier's close does not wait for it.
func (c *serverCarrier) keepAlive(conn KeepAliveConn) {
	from, to := conn.MuxKeepAlive()
	if from < 1 {
		from = 1
	}
	for {
		wait := time.Duration(rollRange(from, to)) * time.Second
		if idle := conn.DownlinkIdle(); idle < wait {
			wait -= idle
		} else if !c.writeKeepAlive(conn) {
			return
		}
		timer := time.NewTimer(wait)
		select {
		case <-c.ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

func (c *serverCarrier) writeKeepAlive(conn KeepAliveConn) bool {
	frame := Frame{Status: StatusKeepAlive}
	if from, to := conn.MuxKeepAliveBytes(); to > 0 {
		if from < 0 {
			from = 0
		}
		if from > maxKeepAlivePadding {
			from = maxKeepAlivePadding
		}
		if to > maxKeepAlivePadding {
			to = maxKeepAlivePadding
		}
		if n := rollRange(from, to); n > 0 {
			frame.Option = OptionData
			frame.Payload = make([]byte, n)
			_, _ = rand.Read(frame.Payload)
		}
	}
	// Check for close as late as possible: a poke the carrier has not
	// started by the time it closes never starts.
	if c.closedFast.Load() {
		return false
	}
	return c.writeFrame(frame) == nil
}
