package xdns

import (
	"bytes"
	"context"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/transport/finalmask"

	"golang.org/x/net/dns/dnsmessage"
)

// The first Xray-core xdns (v26.1.31 to v26.9.9, before "Refactor and new
// parameters") put DNSTT's framing on the wire, which the later xdns this
// package follows no longer reads: a query name carries, in lower-case
// base32, the 8-byte client ID, a byte 224+n, n random bytes and, unless the
// query is a poll, one length byte and the packet; an answer carries
// packets as 2-byte big-endian lengths and data, in one TXT record or in A
// or AAAA records of {index, length, data}. Its settings had their own
// spelling, a resolver as "<domain>[:<method>]+udp://<server>", so a config
// written that way meets a server of that time and speaks this framing.

const (
	legacyPaddingData = 3
	legacyPaddingPoll = 8
	legacyMaxPacket   = 224 // the length byte 224+n tells padding from data
	legacyEDNS0       = 4096
	legacyIPHeader    = 2 // index and length in front of an A/AAAA chunk
	legacyQueueSize   = 256
)

var legacyBase32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// LegacyResolver is one resolver entry of the first xdns: the zone and the
// record type to query it with, and the resolver.
type LegacyResolver struct {
	Zone     string
	Type     uint16
	Resolver ResolverConfig
}

// LegacyConfig is the mask built from the first xdns settings. Only the
// client side is ported: Domains, the server's zones, are kept to name the
// error an inbound gets.
type LegacyConfig struct {
	Domains   []string
	Resolvers []LegacyResolver
}

// HandleDial marks the mask as one that reaches the network only through
// its own resolvers.
func (c *LegacyConfig) HandleDial() {}

func (c *LegacyConfig) WrapPacketConnClient(ctx context.Context, _ net.PacketConn, _ *finalmask.Destination, dialer *finalmask.Dialer) (net.PacketConn, error) {
	return NewLegacyClient(ctx, c, dialer)
}

func (c *LegacyConfig) WrapPacketConnServer(net.PacketConn) (net.PacketConn, error) {
	return nil, errors.New("xdns: the server of the first xdns (compact domains such as \"t.example.com:aaaa\") is not ported; write domains as {names: [...]} for the current xdns")
}

type legacyResolver struct {
	Resolver
	zone  string // lower case, no trailing dot
	qtype uint16
	sends atomic.Uint32
}

type legacyClient struct {
	clientID  [8]byte
	resolvers []*legacyResolver
	zones     []string
	index     int // next resolver, used by the send loop only

	readCh  chan packet
	writeCh chan []byte
	pollCh  chan struct{}
	closeCh chan struct{}
	once    sync.Once
}

// NewLegacyClient opens the resolvers and starts the send and receive loops
// of the first xdns client.
func NewLegacyClient(ctx context.Context, c *LegacyConfig, dialer *finalmask.Dialer) (net.PacketConn, error) {
	if len(c.Resolvers) == 0 {
		return nil, errors.New("xdns: empty resolvers")
	}
	client := &legacyClient{
		readCh:  make(chan packet, legacyQueueSize),
		writeCh: make(chan []byte, legacyQueueSize),
		pollCh:  make(chan struct{}, pollLimit),
		closeCh: make(chan struct{}),
	}
	mustRead(client.clientID[:])
	seen := map[string]bool{}
	for _, entry := range c.Resolvers {
		resolver, err := NewResolver(ctx, entry.Resolver, dialer)
		if err != nil {
			for _, r := range client.resolvers {
				r.Close()
			}
			return nil, err
		}
		zone := strings.ToLower(strings.TrimSuffix(entry.Zone, "."))
		client.resolvers = append(client.resolvers, &legacyResolver{Resolver: resolver, zone: zone, qtype: entry.Type})
		if !seen[zone] {
			seen[zone] = true
			client.zones = append(client.zones, zone)
		}
	}
	for _, r := range client.resolvers {
		go client.recv(r)
	}
	go client.sendLoop()
	return client, nil
}

func (c *legacyClient) closed() bool {
	select {
	case <-c.closeCh:
		return true
	default:
		return false
	}
}

// sendLoop sends the queued packets and, between them, polls: at once after
// an answer carried data, else after a delay that doubles up to 10 s while
// nothing comes, as the first client did.
func (c *legacyClient) sendLoop() {
	delay := initPollDelay
	timer := time.NewTimer(delay)
	defer timer.Stop()
	for {
		var p []byte
		expired := false
		select {
		case p = <-c.writeCh:
		default:
			select {
			case <-c.closeCh:
				return
			case p = <-c.writeCh:
			case <-c.pollCh:
			case <-timer.C:
				expired = true
			}
		}
		if p != nil {
			select {
			case <-c.pollCh:
			default:
			}
		}
		if expired {
			delay = time.Duration(float64(delay) * pollDelayMultiplier)
			if delay > maxPollDelay {
				delay = maxPollDelay
			}
		} else {
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			delay = initPollDelay
		}
		timer.Reset(delay)
		if c.closed() {
			return
		}
		c.send(p)
	}
}

// send writes one query to the next resolver: the one after the last,
// skipping those that were sent more often without an answer since.
func (c *legacyClient) send(p []byte) {
	cur := c.index
	r := c.resolvers[cur]
	if query, err := legacyQuery(p, c.clientID, r.zone, r.qtype); err == nil {
		sent := r.sends.Add(1)
		r.Send(query)
		for {
			c.index = (c.index + 1) % len(c.resolvers)
			if c.index == cur || c.resolvers[c.index].sends.Load() < sent {
				break
			}
		}
	}
}

func (c *legacyClient) recv(r *legacyResolver) {
	buf := make([]byte, finalmask.UDPSize)
	for {
		n, err := r.Read(buf)
		if err != nil {
			return
		}
		packets := legacyAnswerPackets(buf[:n], c.zones)
		if len(packets) == 0 {
			continue
		}
		for _, p := range packets {
			select {
			case c.readCh <- packet{p: p, addr: r.Addr()}:
			case <-c.closeCh:
				return
			default:
			}
		}
		r.sends.Store(0)
		select {
		case c.pollCh <- struct{}{}:
		default:
		}
	}
}

func (c *legacyClient) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case pkt := <-c.readCh:
		return copy(p, pkt.p), pkt.addr, nil
	case <-c.closeCh:
		return 0, nil, net.ErrClosed
	}
}

func (c *legacyClient) WriteTo(p []byte, _ net.Addr) (int, error) {
	if c.closed() {
		return 0, io.ErrClosedPipe
	}
	if len(p) == 0 || len(p) >= legacyMaxPacket {
		// The first client dropped these too; mKCP sizes its packets by
		// its MTU, which a DNS tunnel keeps small.
		return 0, fmt.Errorf("xdns: a %d-byte packet does not fit the first xdns framing (1 to %d bytes)", len(p), legacyMaxPacket-1)
	}
	select {
	case c.writeCh <- append([]byte(nil), p...):
	default: // queue full: dropped, as a congested socket would
	}
	return len(p), nil
}

func (c *legacyClient) Close() error {
	c.once.Do(func() {
		close(c.closeCh)
		for _, r := range c.resolvers {
			r.Close()
		}
	})
	return nil
}

func (c *legacyClient) LocalAddr() net.Addr { return &net.UDPAddr{IP: net.IPv4zero} }

func (c *legacyClient) SetDeadline(time.Time) error { return nil }

func (c *legacyClient) SetReadDeadline(time.Time) error { return nil }

func (c *legacyClient) SetWriteDeadline(time.Time) error { return nil }

// legacyQuery builds the query of the first client for p, a poll when p is
// empty.
func legacyQuery(p []byte, clientID [8]byte, zone string, qtype uint16) ([]byte, error) {
	if len(p) >= legacyMaxPacket {
		return nil, errors.New("xdns: packet too long")
	}
	n := legacyPaddingData
	if len(p) == 0 {
		n = legacyPaddingPoll
	}
	raw := make([]byte, 0, 8+1+n+1+len(p))
	raw = append(raw, clientID[:]...)
	raw = append(raw, byte(legacyMaxPacket+n))
	pad := make([]byte, n)
	mustRead(pad)
	raw = append(raw, pad...)
	if len(p) > 0 {
		raw = append(raw, byte(len(p)))
		raw = append(raw, p...)
	}
	encoded := strings.ToLower(legacyBase32.EncodeToString(raw))
	var name strings.Builder
	for len(encoded) > 0 {
		size := len(encoded)
		if size > 63 {
			size = 63
		}
		name.WriteString(encoded[:size])
		name.WriteByte('.')
		encoded = encoded[size:]
	}
	name.WriteString(zone)
	name.WriteByte('.')
	// The wire form is one byte longer than the dotted name.
	if name.Len()+1 > 255 {
		return nil, errors.New("xdns: query name too long")
	}
	qname, err := dnsmessage.NewName(name.String())
	if err != nil {
		return nil, err
	}
	var id [2]byte
	mustRead(id[:])
	msg := dnsmessage.Message{
		Header: dnsmessage.Header{ID: binary.BigEndian.Uint16(id[:]), RecursionDesired: true},
		Questions: []dnsmessage.Question{{
			Name:  qname,
			Type:  dnsmessage.Type(qtype),
			Class: dnsmessage.ClassINET,
		}},
		Additionals: []dnsmessage.Resource{{
			Header: dnsmessage.ResourceHeader{
				Name:  dnsmessage.MustNewName("."),
				Type:  dnsmessage.TypeOPT,
				Class: dnsmessage.Class(legacyEDNS0),
			},
			Body: &dnsmessage.OPTResource{},
		}},
	}
	return msg.Pack()
}

// legacyAnswerPackets reads the packets an answer of the first server
// carries; nil when it is not one or carries none.
func legacyAnswerPackets(b []byte, zones []string) [][]byte {
	var parser dnsmessage.Parser
	header, err := parser.Start(b)
	if err != nil || !header.Response || header.RCode != dnsmessage.RCodeSuccess {
		return nil
	}
	if err := parser.SkipAllQuestions(); err != nil {
		return nil
	}
	answers, err := parser.AllAnswers()
	if err != nil || len(answers) == 0 {
		return nil
	}
	for _, answer := range answers {
		if !inZones(answer.Header.Name.String(), zones) {
			return nil
		}
	}
	payload := legacyAnswerPayload(answers)
	var packets [][]byte
	for len(payload) >= 2 {
		n := int(binary.BigEndian.Uint16(payload))
		if len(payload) < 2+n {
			break
		}
		packets = append(packets, append([]byte(nil), payload[2:2+n]...))
		payload = payload[2+n:]
	}
	return packets
}

// legacyAnswerPayload joins the data of the answers: the strings of one TXT
// record, or the chunks of A or AAAA records put in order by their index.
func legacyAnswerPayload(answers []dnsmessage.Resource) []byte {
	switch body := answers[0].Body.(type) {
	case *dnsmessage.TXTResource:
		if len(answers) != 1 {
			return nil
		}
		var payload bytes.Buffer
		for _, s := range body.TXT {
			payload.WriteString(s)
		}
		return payload.Bytes()
	case *dnsmessage.AResource, *dnsmessage.AAAAResource:
	default:
		return nil
	}
	if len(answers) > 256 {
		return nil
	}
	parts := make([][]byte, len(answers))
	for _, answer := range answers {
		var data []byte
		switch body := answer.Body.(type) {
		case *dnsmessage.AResource:
			data = body.A[:]
		case *dnsmessage.AAAAResource:
			data = body.AAAA[:]
		}
		if data == nil || answer.Header.Type != answers[0].Header.Type {
			return nil
		}
		idx, n := int(data[0]), int(data[1])
		if idx >= len(parts) || n > len(data)-legacyIPHeader || parts[idx] != nil {
			return nil
		}
		parts[idx] = data[legacyIPHeader : legacyIPHeader+n]
	}
	var payload bytes.Buffer
	for _, part := range parts {
		if part == nil {
			return nil
		}
		payload.Write(part)
	}
	return payload.Bytes()
}

// inZones reports whether name ("a.b.t.example.com.") lies in one of the
// zones, comparing labels without case.
func inZones(name string, zones []string) bool {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	for _, zone := range zones {
		if name == zone || strings.HasSuffix(name, "."+zone) {
			return true
		}
	}
	return false
}
