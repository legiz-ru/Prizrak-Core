// Package xdns is the "xdns" finalmask of Xray-core: datagrams travel as DNS
// queries and answers for a zone the server is authoritative for, through
// the resolvers the client is given. It reads and writes plain DNS on the
// wire, so it is the innermost UDP mask.
package xdns

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/transport/finalmask"
	"github.com/metacubex/randv2"

	"golang.org/x/net/dns/dnsmessage"
)

const (
	initPollDelay       = 500 * time.Millisecond
	maxPollDelay        = 10 * time.Second
	pollDelayMultiplier = 2.0
	pollLimit           = 16
)

var pool4K = sync.Pool{
	New: func() any {
		return make([]byte, 4096)
	},
}

type packet struct {
	p    []byte
	addr net.Addr
}

type xdnsClient struct {
	dialer *finalmask.Dialer

	clientID  ClientID
	fragID    atomic.Uint32
	domains   []*Domain
	extraPoll int32

	resolvers     []Resolver
	resolverSends []atomic.Uint32
	resolverIndex atomic.Uint32

	readCh  chan packet
	poolCh  chan struct{}
	closeCh chan struct{}
	wg      sync.WaitGroup
	mu      sync.Mutex
}

// NewClient opens the resolvers and starts polling the server for downlink
// data.
func NewClient(ctx context.Context, c *Config, dialer *finalmask.Dialer) (net.PacketConn, error) {
	if len(c.Domains) == 0 {
		return nil, errors.New("xdns: empty domains")
	}
	if len(c.Resolvers) == 0 {
		return nil, errors.New("xdns: empty resolvers")
	}
	if c.ExtraPoll < 0 || c.ExtraPoll > 3 {
		return nil, errors.New("xdns: extra-poll must be between 0 and 3")
	}
	domains := make([]*Domain, 0, len(c.Domains))
	for i := range c.Domains {
		types := c.Domains[i].Types
		if len(types) == 0 {
			types = []uint16{TypeTXT}
		}
		domain, err := NewDomain(c.Domains[i].Name, c.Domains[i].LenLimit, c.Domains[i].LabelLimit, types, c.Domains[i].EDNS0)
		if err != nil {
			return nil, err
		}
		domains = append(domains, domain)
	}
	resolvers := make([]Resolver, 0, len(c.Resolvers))
	for i := range c.Resolvers {
		resolver, err := NewResolver(ctx, c.Resolvers[i], dialer)
		if err != nil {
			for _, resolver := range resolvers {
				resolver.Close()
			}
			return nil, err
		}
		resolvers = append(resolvers, resolver)
	}
	client := &xdnsClient{
		dialer: dialer,

		clientID:  NewClientID(),
		domains:   domains,
		extraPoll: c.ExtraPoll,

		resolvers:     resolvers,
		resolverSends: make([]atomic.Uint32, len(c.Resolvers)),

		readCh:  make(chan packet),
		poolCh:  make(chan struct{}, pollLimit),
		closeCh: make(chan struct{}),
	}
	go client.run()
	return client, nil
}

func (c *xdnsClient) closed() bool {
	select {
	case <-c.closeCh:
		return true
	default:
		return false
	}
}

// send packs p into one or more queries; an empty p is a poll.
func (c *xdnsClient) send(p []byte) {
	domain := c.domains[randv2.IntN(len(c.domains))]
	qtype := domain.types[randv2.IntN(len(domain.types))]

	var buf [512]byte
	var data [255]byte

	send := func(p []byte) {
		msg := dnsmessage.Message{
			Header: dnsmessage.Header{
				RecursionDesired: true,
			},
			Questions: []dnsmessage.Question{
				{
					Name:  domain.Encode(p),
					Type:  dnsmessage.Type(qtype),
					Class: dnsmessage.ClassINET,
				},
			},
		}
		if domain.edns0 > 0 {
			msg.Additionals = []dnsmessage.Resource{
				{
					Header: dnsmessage.ResourceHeader{
						Name:  dnsmessage.MustNewName("."),
						Type:  dnsmessage.TypeOPT,
						Class: dnsmessage.Class(domain.edns0),
						TTL:   0,
					},
					Body: &dnsmessage.OPTResource{},
				},
			}
		}
		pack, err := msg.AppendPack(buf[:0])
		if err != nil {
			panic(err)
		}
		mustRead(pack[:2])

		// Spread the queries over the resolvers, favouring those that
		// answered recently.
		index := c.resolverIndex.Load()
		cur := c.resolverSends[index].Add(1)
		i := index
		for {
			i++
			if i == uint32(len(c.resolvers)) {
				i = 0
			}
			if i == index {
				break
			}
			if cur > c.resolverSends[i].Load() {
				break
			}
		}
		c.resolverIndex.Store(i)
		c.resolvers[index].Send(pack)
	}

	if len(p) == 0 {
		copy(data[:], c.clientID[:])
		data[0] |= typeMap[qtype]
		data[8] = 8
		mustRead(data[9:17])
		send(data[:17])
		return
	}

	if len(p) <= domain.cap-12 {
		copy(data[:], c.clientID[:])
		data[0] |= typeMap[qtype]
		data[8] = 3
		mustRead(data[9:12])
		copy(data[12:], p)
		send(data[:12+len(p)])
		return
	}

	if len(p) <= 255*(domain.cap-15) {
		copy(data[:], c.clientID[:])
		data[0] |= typeMap[qtype]
		data[8] = 3 | 0xC0
		mustRead(data[9:12])

		fragID := byte(c.fragID.Add(1))
		fragN := len(p) / (domain.cap - 15)
		if len(p)%(domain.cap-15) > 0 {
			fragN++
		}

		for i := 0; i < fragN; i++ {
			data[12] = fragID
			data[13] = byte(i)
			data[14] = byte(fragN)
			size := len(p)
			if size > domain.cap-15 {
				size = domain.cap - 15
			}
			copy(data[15:], p[:size])
			send(data[:15+size])
			p = p[size:]
		}
		return
	}

	log.Warnln("[finalmask] xdns: dropping a %d-byte packet, too large for the domain", len(p))
}

func mustRead(b []byte) {
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
}

// read unpacks an answer; true when it carried data.
func (c *xdnsClient) read(buf []byte, addr net.Addr) bool {
	msg := dnsmessage.Message{}
	if err := msg.Unpack(buf); err != nil {
		return false
	}
	if !msg.Header.Response || msg.Header.Truncated || msg.Header.RCode != dnsmessage.RCodeSuccess || len(msg.Questions) != 1 {
		return false
	}

	var domain *Domain
	for i := range c.domains {
		if c.domains[i].IsDomain(msg.Questions[0].Name) {
			domain = c.domains[i]
			break
		}
	}
	if domain == nil || !domain.HasType(uint16(msg.Questions[0].Type)) {
		return false
	}

	resp := NewResp(msg, domain, 0)

	p := pool4K.Get().([]byte)
	n := resp.Decode(p)
	p = p[:n]

	b := p
	var bs [][]byte
	for len(b) > 1 {
		last := b[0]&0xC0 == 0xC0
		length := int(b[0]&0x3F)<<8 | int(b[1])
		b = b[2:]
		if length > len(b) {
			bs = nil
			break
		}
		packet := make([]byte, length)
		copy(packet, b)
		bs = append(bs, packet)
		if last {
			break
		}
		b = b[length:]
		if len(b) < 2 {
			bs = nil
		}
	}
	pool4K.Put(p[:cap(p)])

	for i := range bs {
		select {
		case <-c.closeCh:
			return true
		case c.readCh <- packet{p: bs[i], addr: addr}:
		}
	}
	return len(bs) > 0
}

func (c *xdnsClient) run() {
	for i := range c.resolvers {
		c.wg.Add(1)
		go c.recv(i)
	}

	c.wg.Add(1)
	go c.poll()

	c.wg.Wait()
	close(c.readCh)
	close(c.poolCh)
}

func (c *xdnsClient) recv(i int) {
	defer c.wg.Done()

	var buf [4096]byte
	for {
		n, err := c.resolvers[i].Read(buf[:])
		if err != nil {
			if c.closed() {
				return
			}
			log.Warnln("[finalmask] xdns: resolver %d stopped: %v", i, err)
			return
		}
		if c.read(buf[:n], c.resolvers[i].Addr()) {
			c.resolverSends[i].Store(0)
			select {
			case c.poolCh <- struct{}{}:
			default:
			}
		}
	}
}

// poll asks the server for downlink data, quickly after data came and more
// slowly while nothing does.
func (c *xdnsClient) poll() {
	defer c.wg.Done()

	select {
	case <-c.closeCh:
	case <-c.poolCh:
	}
	delay := initPollDelay
	ticker := time.NewTicker(delay)
	defer ticker.Stop()
	for {
		select {
		case <-c.closeCh:
			return
		case <-c.poolCh:
			delay = initPollDelay
		case <-ticker.C:
			delay *= pollDelayMultiplier
			if delay > maxPollDelay {
				delay = maxPollDelay
			}
		}
		if c.closed() {
			return
		}
		ticker.Reset(delay)
		c.send(nil)
		for i := int32(0); i < c.extraPoll; i++ {
			c.send(nil)
		}
	}
}

func (c *xdnsClient) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	packet, ok := <-c.readCh
	if ok {
		return copy(p, packet.p), packet.addr, nil
	}
	return 0, nil, io.ErrClosedPipe
}

func (c *xdnsClient) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	// Send without c.mu: a resolver write can block until Close closes the
	// resolver, and Close needs c.mu to reach it. A write that races Close
	// reaches a closed resolver, which drops it.
	if c.closed() {
		return 0, io.ErrClosedPipe
	}
	if len(p) == 0 || len(p) > 4096 {
		return 0, errors.New("xdns: invalid packet size")
	}
	c.send(p)
	for i := int32(0); i < c.extraPoll; i++ {
		c.send(nil)
	}
	return len(p), nil
}

func (c *xdnsClient) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed() {
		return nil
	}
	close(c.closeCh)
	for i := range c.resolvers {
		c.resolvers[i].Close()
	}
	return nil
}

func (c *xdnsClient) LocalAddr() net.Addr { return &net.UDPAddr{IP: net.IPv4zero} }

func (c *xdnsClient) SetDeadline(t time.Time) error { return nil }

func (c *xdnsClient) SetReadDeadline(t time.Time) error { return nil }

func (c *xdnsClient) SetWriteDeadline(t time.Time) error { return nil }

// ClientID identifies a client to the server; it travels in every query.
type ClientID [8]byte

func NewClientID() ClientID {
	var id ClientID
	mustRead(id[:])
	id[0] &= 0xFC
	return id
}

func ClientIDFromRaw(id [8]byte) ClientID {
	id[0] &= 0xFC
	return id
}

func ClientIDFromAddr(addr *net.UDPAddr) ClientID {
	return ClientID(addr.IP[8:])
}

// Addr is the fake address the server's packet connection reports for the
// client: fd00::/64 with the ID in the host part.
func (id ClientID) Addr() *net.UDPAddr {
	var ip [16]byte
	ip[0] = 0xFD
	copy(ip[8:], id[:])
	return &net.UDPAddr{IP: ip[:]}
}
