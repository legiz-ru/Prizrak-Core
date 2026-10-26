// Package udphop is the "udphop" finalmask of Xray-core: the client changes
// its local UDP socket, the remote address or both at random intervals, so
// one QUIC connection does not stay on one 5-tuple.
package udphop

import (
	"context"
	"crypto/rand"
	goerrors "errors"
	"fmt"
	mrand "github.com/metacubex/randv2"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/contextutils"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/transport/finalmask"
)

// Config is the built mask.
type Config struct {
	Local       bool // open a new local socket on every hop
	Remote      bool // pick a new remote IP and port on every hop
	RemoteOnce  bool // pick a remote IP and port once per connection
	IntervalMin int64
	IntervalMax int64 // seconds
	RemoteIPs   []netip.Prefix
	RemotePorts []uint16
}

// Option is the mask's settings as written in the config. Mode is a
// comma-separated set of intervalLocal, intervalRemote and perConnRemote.
type Option struct {
	Mode        string          `proxy:"mode,omitempty"`
	Interval    finalmask.Range `proxy:"interval,omitempty"` // seconds, 30 by default, at least 5
	RemoteIPs   []string        `proxy:"remote-ips,omitempty"`
	RemotePorts []string        `proxy:"remote-ports,omitempty"` // "443", "20000-30000"
}

func New(o Option) (*Config, error) {
	c := &Config{}
	for _, mode := range strings.Split(o.Mode, ",") {
		switch strings.ToLower(strings.TrimSpace(mode)) {
		case "":
		case "intervallocal":
			c.Local = true
		case "intervalremote":
			c.Remote = true
		case "perconnremote":
			c.RemoteOnce = true
		default:
			return nil, fmt.Errorf("udphop: invalid mode %q, want intervalLocal, intervalRemote or perConnRemote", mode)
		}
	}
	if !c.Local && !c.Remote && !c.RemoteOnce {
		return nil, goerrors.New("udphop: mode is required")
	}
	for _, ip := range o.RemoteIPs {
		if prefix, err := netip.ParsePrefix(ip); err == nil {
			c.RemoteIPs = append(c.RemoteIPs, prefix.Masked())
			continue
		}
		if addr, err := netip.ParseAddr(ip); err == nil {
			c.RemoteIPs = append(c.RemoteIPs, netip.PrefixFrom(addr, addr.BitLen()))
			continue
		}
		return nil, fmt.Errorf("udphop: invalid ip %q", ip)
	}
	for _, ports := range o.RemotePorts {
		from, to, err := finalmask.ParseRange(ports)
		if err != nil || from < 1 || to > 65535 {
			return nil, fmt.Errorf("udphop: invalid port range %q", ports)
		}
		if from > to {
			from, to = to, from
		}
		if to-from > 65535 {
			return nil, fmt.Errorf("udphop: invalid port range %q", ports)
		}
		for p := from; p <= to; p++ {
			c.RemotePorts = append(c.RemotePorts, uint16(p))
		}
	}
	if (c.Remote || c.RemoteOnce) && len(c.RemoteIPs) == 0 && len(c.RemotePorts) == 0 {
		return nil, goerrors.New("udphop: a remote mode needs remote-ips or remote-ports")
	}
	from, to := o.Interval.From, o.Interval.To
	if from == 0 && to == 0 {
		from, to = 30, 30
	}
	if from > to {
		from, to = to, from
	}
	if from < 5 {
		return nil, goerrors.New("udphop: interval must be at least 5 seconds")
	}
	c.IntervalMin, c.IntervalMax = int64(from), int64(to)
	return c, nil
}

func (c *Config) HandleDial() {}

func (c *Config) WrapPacketConnClient(ctx context.Context, _ net.PacketConn, dest *finalmask.Destination, dialer *finalmask.Dialer) (net.PacketConn, error) {
	return NewConn(ctx, c, dest, dialer)
}

func (c *Config) WrapPacketConnServer(net.PacketConn) (net.PacketConn, error) {
	return nil, goerrors.New("udphop: client only")
}

var pool = sync.Pool{
	New: func() any {
		return make([]byte, finalmask.UDPSize)
	},
}

type packet struct {
	p    []byte
	addr net.Addr
	err  error
}

type hopConn struct {
	ctx    context.Context
	dialer *finalmask.Dialer
	config *Config

	deadline      time.Time
	readDeadline  time.Time
	writeDeadline time.Time

	pre     net.PacketConn
	cur     net.PacketConn
	addr    *net.UDPAddr
	readCh  chan packet
	closeCh chan struct{}
	wg      sync.WaitGroup
	mu      sync.RWMutex
}

// NewConn opens the first socket to dest, which it changes to a random
// remote when the config asks for one, and starts hopping.
func NewConn(ctx context.Context, c *Config, dest *finalmask.Destination, dialer *finalmask.Dialer) (net.PacketConn, error) {
	if c.IntervalMin < 5 || c.IntervalMax < 5 {
		return nil, goerrors.New("udphop: invalid interval")
	}
	if c.Remote || c.RemoteOnce {
		if len(c.RemoteIPs) > 0 {
			dest.Host = randPrefix(c.RemoteIPs[mrand.IntN(len(c.RemoteIPs))]).String()
		}
		if len(c.RemotePorts) > 0 {
			dest.Port = c.RemotePorts[mrand.IntN(len(c.RemotePorts))]
		}
	}
	conn, raddr, err := dialer.DialUDP(ctx, dest.Addr())
	if err != nil {
		return nil, err
	}
	addr, ok := raddr.(*net.UDPAddr)
	if !ok {
		_ = conn.Close()
		return nil, fmt.Errorf("udphop: remote address is %T, not UDP", raddr)
	}
	hop := &hopConn{
		ctx:     contextutils.WithoutCancel(ctx),
		dialer:  dialer,
		config:  c,
		cur:     conn,
		addr:    addr,
		readCh:  make(chan packet),
		closeCh: make(chan struct{}),
	}
	go hop.run()
	hop.wg.Add(1)
	go hop.recv(hop.cur)
	return hop, nil
}

func (c *hopConn) closed() bool {
	select {
	case <-c.closeCh:
		return true
	default:
		return false
	}
}

func (c *hopConn) interval() time.Duration {
	return time.Second * time.Duration(finalmask.RandBetween(c.config.IntervalMin, c.config.IntervalMax+1))
}

func (c *hopConn) run() {
	ticker := time.NewTicker(c.interval())
	defer ticker.Stop()
	for {
		select {
		case <-c.closeCh:
			return
		case <-ticker.C:
			ticker.Reset(c.interval())
			c.hop()
		}
	}
}

func (c *hopConn) hop() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed() {
		return
	}
	oldIP := c.addr.IP
	oldPort := c.addr.Port
	if c.config.Remote {
		if len(c.config.RemoteIPs) > 0 {
			c.addr.IP = randPrefix(c.config.RemoteIPs[mrand.IntN(len(c.config.RemoteIPs))]).AsSlice()
		}
		if len(c.config.RemotePorts) > 0 {
			c.addr.Port = int(c.config.RemotePorts[mrand.IntN(len(c.config.RemotePorts))])
		}
	}
	if c.config.Local {
		conn, _, err := c.dialer.DialUDP(c.ctx, net.JoinHostPort(c.addr.IP.String(), strconv.Itoa(c.addr.Port)))
		if err != nil {
			c.addr.IP = oldIP
			c.addr.Port = oldPort
			log.Warnln("[finalmask] udphop: hop failed: %v", err)
			return
		}
		_ = conn.SetDeadline(c.deadline)
		_ = conn.SetReadDeadline(c.readDeadline)
		_ = conn.SetWriteDeadline(c.writeDeadline)
		if c.pre != nil {
			_ = c.pre.Close()
		}
		c.pre = c.cur
		c.cur = conn
		c.wg.Add(1)
		go c.recv(c.cur)
	}
}

func (c *hopConn) recv(conn net.PacketConn) {
	defer c.wg.Done()

	for {
		p := pool.Get().([]byte)
		n, addr, err := conn.ReadFrom(p)
		if err != nil {
			pool.Put(p[:cap(p)])
			if c.closed() {
				return
			}
			var netErr net.Error
			if goerrors.As(err, &netErr) && netErr.Timeout() {
				select {
				case c.readCh <- packet{err: err}:
				case <-c.closeCh:
					return
				}
				continue
			}
			// The previous socket of a hop is closed by hop(); any other
			// error ends this socket's reads.
			c.mu.RLock()
			current := conn == c.cur
			c.mu.RUnlock()
			if current {
				log.Warnln("[finalmask] udphop: recv failed: %v", err)
			}
			return
		}
		select {
		case c.readCh <- packet{p: p[:n], addr: addr}:
		case <-c.closeCh:
			pool.Put(p[:cap(p)])
			return
		}
	}
}

func (c *hopConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	packet, ok := <-c.readCh
	if ok {
		if packet.p != nil {
			n = copy(p, packet.p)
			pool.Put(packet.p[:cap(packet.p)])
		}
		return n, packet.addr, packet.err
	}
	return 0, nil, io.ErrClosedPipe
}

// WriteTo sends to the current remote whatever addr says: the hop decides
// where the peer is.
func (c *hopConn) WriteTo(p []byte, _ net.Addr) (n int, err error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.closed() {
		return 0, io.ErrClosedPipe
	}
	_, err = c.cur.WriteTo(p, c.addr)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *hopConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed() {
		return nil
	}
	close(c.closeCh)
	if c.pre != nil {
		_ = c.pre.Close()
	}
	_ = c.cur.Close()
	c.wg.Wait()
	close(c.readCh)
	return nil
}

func (c *hopConn) LocalAddr() net.Addr {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.cur.LocalAddr()
}

// RemoteAddr is the current remote, for the layers that want to know it.
func (c *hopConn) RemoteAddr() net.Addr {
	c.mu.RLock()
	defer c.mu.RUnlock()
	addr := *c.addr
	return &addr
}

func (c *hopConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.deadline = t
	if c.pre != nil {
		_ = c.pre.SetDeadline(t)
	}
	return c.cur.SetDeadline(t)
}

func (c *hopConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.readDeadline = t
	if c.pre != nil {
		_ = c.pre.SetReadDeadline(t)
	}
	return c.cur.SetReadDeadline(t)
}

func (c *hopConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writeDeadline = t
	if c.pre != nil {
		_ = c.pre.SetWriteDeadline(t)
	}
	return c.cur.SetWriteDeadline(t)
}

// randPrefix draws a random address inside p.
func randPrefix(p netip.Prefix) netip.Addr {
	if p.IsSingleIP() {
		return p.Addr()
	}
	b := p.Addr().AsSlice()
	bits := p.Bits()
	var random [16]byte
	if _, err := rand.Read(random[:len(b)]); err != nil {
		panic(err)
	}
	i := bits / 8
	j := bits % 8
	if i+1 < len(b) {
		copy(b[i+1:], random[i+1:len(b)])
	}
	if i < len(b) {
		mask := byte(0xff << (8 - j))
		b[i] = (b[i] & mask) | (random[i] &^ mask)
	}
	addr, _ := netip.AddrFromSlice(b)
	return addr
}
