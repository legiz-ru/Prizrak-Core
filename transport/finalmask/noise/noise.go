// Package noise is the "noise" finalmask of Xray-core: before the first
// datagram to a peer, and again after a reset interval, it sends a few
// datagrams of noise that look like another protocol's handshake.
package noise

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/transport/finalmask"
)

type SegmentKind int

const (
	SegmentBytes SegmentKind = iota
	SegmentRandom
	SegmentRandomASCII
	SegmentRandomDigit
	SegmentTimestamp
	SegmentCounter
	SegmentNonce
)

// Segment is one part of a composed noise packet.
type Segment struct {
	Kind    SegmentKind
	Bytes   []byte
	MinSize int64 // random kinds: size in [MinSize, MaxSize]
	MaxSize int64
}

// Item is one noise packet: Segments when composed, otherwise RandMin..RandMax
// random bytes in [RandRangeMin, RandRangeMax], otherwise Packet.
type Item struct {
	RandMin, RandMax           int64
	RandRangeMin, RandRangeMax int32
	Packet                     []byte
	DelayMin, DelayMax         int64 // milliseconds after the packet
	Segments                   []*Segment
}

type Config struct {
	ResetMin, ResetMax int64 // seconds; 0 sends the noise once per peer
	Items              []*Item
}

const asciiLetters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

func (c *Config) WrapPacketConnClient(_ context.Context, conn net.PacketConn, _ *finalmask.Destination, _ *finalmask.Dialer) (net.PacketConn, error) {
	return NewConn(c, conn), nil
}

func (c *Config) WrapPacketConnServer(conn net.PacketConn) (net.PacketConn, error) {
	return NewConn(c, conn), nil
}

type noiseConn struct {
	net.PacketConn
	config  *Config
	m       map[string]time.Time
	mu      sync.Mutex
	counter atomic.Uint32
}

func NewConn(c *Config, raw net.PacketConn) net.PacketConn {
	return &noiseConn{
		PacketConn: raw,
		config:     c,
		m:          make(map[string]time.Time),
	}
}

func (c *noiseConn) buildPacket(item *Item) []byte {
	if len(item.Segments) == 0 {
		if item.RandMax > 0 {
			buf := make([]byte, finalmask.RandBetween(item.RandMin, item.RandMax))
			finalmask.RandBytesBetween(buf, byte(item.RandRangeMin), byte(item.RandRangeMax))
			return buf
		}
		return item.Packet
	}
	var out []byte
	for _, seg := range item.Segments {
		out = append(out, c.buildSegment(seg)...)
	}
	return out
}

func (c *noiseConn) buildSegment(seg *Segment) []byte {
	switch seg.Kind {
	case SegmentBytes:
		return seg.Bytes
	case SegmentTimestamp:
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, uint32(time.Now().Unix()))
		return b
	case SegmentCounter:
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, c.counter.Add(1))
		return b
	case SegmentNonce:
		b := make([]byte, 8)
		mustRead(b)
		return b
	default:
		size := finalmask.RandBetween(seg.MinSize, seg.MaxSize+1)
		if size <= 0 {
			return nil
		}
		buf := make([]byte, size)
		mustRead(buf)
		switch seg.Kind {
		case SegmentRandomASCII:
			for i := range buf {
				buf[i] = asciiLetters[int(buf[i])%len(asciiLetters)]
			}
		case SegmentRandomDigit:
			for i := range buf {
				buf[i] = '0' + buf[i]%10
			}
		}
		return buf
	}
}

func mustRead(b []byte) {
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
}

func (c *noiseConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	t := c.m[addr.String()]

	if t.IsZero() || (c.config.ResetMax > 0 && time.Now().After(t)) {
		for _, item := range c.config.Items {
			_, _ = c.PacketConn.WriteTo(c.buildPacket(item), addr)
			if d := finalmask.RandBetween(item.DelayMin, item.DelayMax); d > 0 {
				time.Sleep(time.Duration(d) * time.Millisecond)
			}
		}
	}

	c.m[addr.String()] = time.Now().Add(time.Duration(finalmask.RandBetween(c.config.ResetMin, c.config.ResetMax)) * time.Second)

	return c.PacketConn.WriteTo(p, addr)
}
