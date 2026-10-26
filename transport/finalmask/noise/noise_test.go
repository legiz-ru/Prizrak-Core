package noise

import (
	"bytes"
	"encoding/binary"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/mihomo/transport/finalmask"

	"github.com/stretchr/testify/require"
)

type fakePacketConn struct {
	mu      sync.Mutex
	written [][]byte
}

func (c *fakePacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.written = append(c.written, bytes.Clone(p))
	return len(p), nil
}

func (c *fakePacketConn) packets() [][]byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.written
}

func (c *fakePacketConn) ReadFrom(_ []byte) (int, net.Addr, error) { return 0, nil, nil }
func (c *fakePacketConn) Close() error                             { return nil }
func (c *fakePacketConn) LocalAddr() net.Addr                      { return &net.UDPAddr{} }
func (c *fakePacketConn) SetDeadline(time.Time) error              { return nil }
func (c *fakePacketConn) SetReadDeadline(time.Time) error          { return nil }
func (c *fakePacketConn) SetWriteDeadline(time.Time) error         { return nil }

func newTestConn() *noiseConn {
	return NewConn(&Config{}, &fakePacketConn{}).(*noiseConn)
}

func TestBuildSegments(t *testing.T) {
	c := newTestConn()
	require.Equal(t, []byte{0x0d, 0x0a}, c.buildSegment(&Segment{Kind: SegmentBytes, Bytes: []byte{0x0d, 0x0a}}))

	before := time.Now().Unix()
	ts := c.buildSegment(&Segment{Kind: SegmentTimestamp})
	require.Len(t, ts, 4)
	require.GreaterOrEqual(t, int64(binary.BigEndian.Uint32(ts)), before)

	require.Equal(t, uint32(1), binary.BigEndian.Uint32(c.buildSegment(&Segment{Kind: SegmentCounter})))
	require.Equal(t, uint32(2), binary.BigEndian.Uint32(c.buildSegment(&Segment{Kind: SegmentCounter})))

	a := c.buildSegment(&Segment{Kind: SegmentNonce})
	b := c.buildSegment(&Segment{Kind: SegmentNonce})
	require.Len(t, a, 8)
	require.NotEqual(t, a, b)

	for i := 0; i < 100; i++ {
		require.Len(t, c.buildSegment(&Segment{Kind: SegmentRandom, MinSize: 24, MaxSize: 24}), 24)
		n := len(c.buildSegment(&Segment{Kind: SegmentRandom, MinSize: 20, MaxSize: 32}))
		require.GreaterOrEqual(t, n, 20)
		require.LessOrEqual(t, n, 32)
		for _, b := range c.buildSegment(&Segment{Kind: SegmentRandomASCII, MinSize: 40, MaxSize: 40}) {
			require.True(t, (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z'), "not a letter: %q", b)
		}
		for _, b := range c.buildSegment(&Segment{Kind: SegmentRandomDigit, MinSize: 40, MaxSize: 40}) {
			require.True(t, b >= '0' && b <= '9', "not a digit: %q", b)
		}
	}
}

func TestBuildPacket(t *testing.T) {
	c := newTestConn()
	got := c.buildPacket(&Item{Segments: []*Segment{
		{Kind: SegmentBytes, Bytes: []byte{0x0d, 0x0a, 0x0d, 0x0a}},
		{Kind: SegmentTimestamp},
		{Kind: SegmentRandom, MinSize: 24, MaxSize: 24},
	}})
	require.Len(t, got, 4+4+24)
	require.Equal(t, []byte{0x0d, 0x0a, 0x0d, 0x0a}, got[:4])

	require.Equal(t, []byte{1, 2, 3}, c.buildPacket(&Item{Packet: []byte{1, 2, 3}}))
	require.Len(t, c.buildPacket(&Item{RandMin: 16, RandMax: 17}), 16)
	for _, b := range c.buildPacket(&Item{RandMin: 64, RandMax: 65, RandRangeMin: 'a', RandRangeMax: 'f'}) {
		require.True(t, b >= 'a' && b <= 'f')
	}
}

func TestWriteToSendsNoiseThenPayload(t *testing.T) {
	raw := &fakePacketConn{}
	c := NewConn(&Config{Items: []*Item{
		{Segments: []*Segment{{Kind: SegmentBytes, Bytes: []byte{0x0d, 0x0a, 0x0d, 0x0a}}, {Kind: SegmentRandom, MinSize: 8, MaxSize: 8}}},
		{RandMin: 40, RandMax: 41},
	}}, raw)
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 51820}
	payload := []byte("real-handshake")
	_, err := c.WriteTo(payload, addr)
	require.NoError(t, err)

	sent := raw.packets()
	require.Len(t, sent, 3)
	require.Len(t, sent[0], 12)
	require.Equal(t, []byte{0x0d, 0x0a, 0x0d, 0x0a}, sent[0][:4])
	require.Len(t, sent[1], 40)
	require.Equal(t, payload, sent[2])

	// Without a reset the noise is sent once per peer.
	_, err = c.WriteTo(payload, addr)
	require.NoError(t, err)
	require.Len(t, raw.packets(), 4)

	// Another peer gets its own noise.
	_, err = c.WriteTo(payload, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 2), Port: 1})
	require.NoError(t, err)
	require.Len(t, raw.packets(), 7)
}

func TestParseExp(t *testing.T) {
	segs, err := ParseExp("<b 0x0d0a> <t><c> <n> <r 24> <rc 8-16> <rd 4>")
	require.NoError(t, err)
	require.Len(t, segs, 7)
	require.Equal(t, []byte{0x0d, 0x0a}, segs[0].Bytes)
	require.Equal(t, SegmentTimestamp, segs[1].Kind)
	require.Equal(t, SegmentCounter, segs[2].Kind)
	require.Equal(t, SegmentNonce, segs[3].Kind)
	require.Equal(t, int64(24), segs[4].MinSize)
	require.Equal(t, SegmentRandomASCII, segs[5].Kind)
	require.Equal(t, int64(8), segs[5].MinSize)
	require.Equal(t, int64(16), segs[5].MaxSize)
	require.Equal(t, SegmentRandomDigit, segs[6].Kind)

	for _, bad := range []string{"", "<x 1>", "<r>", "<t 1>", "junk <t>", "<b zz>"} {
		_, err := ParseExp(bad)
		require.Error(t, err, bad)
	}
}

func TestOption(t *testing.T) {
	cfg, err := New(Option{
		Reset: finalmask.Range{From: 10, To: 20},
		Noise: []ItemOption{
			{Rand: finalmask.Range{From: 50, To: 100}, RandRange: &finalmask.Range{From: 0x20, To: 0x7e}, Delay: finalmask.Range{From: 10, To: 20}},
			{Type: "str", Packet: "hello"},
			{Type: "hex", Packet: "0d0a"},
			{Type: "exp", Packet: "<b 16> <r 32>"},
			{Packet: []any{1, 2, 3}},
		},
	})
	require.NoError(t, err)
	require.Equal(t, int64(10), cfg.ResetMin)
	require.Equal(t, int64(20), cfg.ResetMax)
	require.Len(t, cfg.Items, 5)
	require.Equal(t, int64(50), cfg.Items[0].RandMin)
	require.Equal(t, int32(0x7e), cfg.Items[0].RandRangeMax)
	require.Equal(t, int64(20), cfg.Items[0].DelayMax)
	require.Equal(t, []byte("hello"), cfg.Items[1].Packet)
	require.Equal(t, []byte{0x0d, 0x0a}, cfg.Items[2].Packet)
	require.Len(t, cfg.Items[3].Segments, 2)
	require.Equal(t, []byte{1, 2, 3}, cfg.Items[4].Packet)

	_, err = New(Option{Noise: []ItemOption{{Rand: finalmask.Range{From: 1, To: 2}, Packet: "x"}}})
	require.Error(t, err)
	_, err = New(Option{Noise: []ItemOption{{}}})
	require.Error(t, err)
}
