// Ported from Xray-core v26.11.9 transport/internet/xdrive
// (https://github.com/XTLS/Xray-core), which is licensed under the Mozilla
// Public License 2.0; this file stays under MPL-2.0.
// SPDX-License-Identifier: MPL-2.0

package xdrive

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	C "github.com/metacubex/mihomo/constant"
)

const (
	protocolName = "xdrive"
	sessionsDir  = "sessions"
	streamsDir   = "streams"
	uplinkDir    = "c2s"
	downlinkDir  = "s2c"
)

const (
	spareCount    = 2
	spareIdleStop = 10 * time.Minute
)

func newSessionID() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", newError("failed to generate session id").Base(err)
	}
	return hex.EncodeToString(buf), nil
}

func announceName(session string, at time.Time) string {
	return fmt.Sprintf("%s/%d-%s", sessionsDir, at.UnixNano(), session)
}

func parseAnnounce(entry string) (string, time.Time, bool) {
	dash := strings.IndexByte(entry, '-')
	if dash <= 0 || dash == len(entry)-1 {
		return "", time.Time{}, false
	}
	nanos, err := strconv.ParseInt(entry[:dash], 10, 64)
	if err != nil {
		return "", time.Time{}, false
	}
	return entry[dash+1:], time.Unix(0, nanos), true
}

func sessionPrefix(session string) string {
	return streamsDir + "/" + session
}

func uplinkPrefix(session string) string {
	return sessionPrefix(session) + "/" + uplinkDir
}

func downlinkPrefix(session string) string {
	return sessionPrefix(session) + "/" + downlinkDir
}

type spareRing struct {
	storage Storage
	session string
	ring    ring
	at      time.Time
}

type spareBox struct {
	ch   chan spareRing
	busy atomic.Bool
	last atomic.Int64
	stop atomic.Bool

	// mu orders a new spare going into ch against Close draining ch, so
	// that no ring is left behind a closed client; ctx ends the ring that
	// is being made when the client closes.
	mu     sync.Mutex
	ctx    context.Context
	cancel context.CancelFunc
}

// put adds a spare unless the client is closed or the box is full.
func (b *spareBox) put(s spareRing) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.stop.Load() {
		return false
	}
	select {
	case b.ch <- s:
		return true
	default:
		return false
	}
}

// Client dials sessions of the transport. It keeps what Xray-core keeps per
// config in package variables, the spare rings of a storage and the storage.
type Client struct {
	config *Config
	dialer *Dialer
	build  func() (Storage, error)
	box    *spareBox

	mu      sync.Mutex
	storage Storage
}

// NewClient returns a Client over a Config that went through Normalize.
func NewClient(config *Config, dialer *Dialer) *Client {
	box := &spareBox{ch: make(chan spareRing, spareCount)}
	box.ctx, box.cancel = context.WithCancel(context.Background())
	c := &Client{
		config: config,
		dialer: dialer,
		box:    box,
	}
	c.build = func() (Storage, error) { return newStorage(config, dialer) }
	return c
}

// shared returns the storage that the sessions of c have in common, the one
// that holds its token and connections.
func (c *Client) shared() (Storage, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.storage != nil {
		return c.storage, nil
	}
	storage, err := c.build()
	if err != nil {
		return nil, err
	}
	c.storage = storage
	return storage, nil
}

// Close drops the spare rings, the one being made too. Sessions that were
// dialed go on until they close.
func (c *Client) Close() error {
	box := c.box
	box.mu.Lock()
	box.stop.Store(true)
	for drained := false; !drained; {
		select {
		case s := <-box.ch:
			go dropSpare(s)
		default:
			drained = true
		}
	}
	box.mu.Unlock()
	box.cancel()

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.storage != nil {
		err := c.storage.Close()
		c.storage = nil
		return err
	}
	return nil
}

func dropSpare(s spareRing) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	s.storage.Delete(ctx, sessionPrefix(s.session))
	s.storage.Close()
}

func (c *Client) takeSpare(p params) (spareRing, bool) {
	box := c.box
	for {
		select {
		case s := <-box.ch:
			if time.Since(s.at) < p.sessionTTL*2/3 {
				return s, true
			}
			go dropSpare(s)
		default:
			return spareRing{}, false
		}
	}
}

func (c *Client) warmSpares(p params) {
	c.box.last.Store(time.Now().UnixNano())
	c.fillSpares(p)
}

func (c *Client) fillSpares(p params) {
	box := c.box
	if !box.busy.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer box.busy.Store(false)
		for n := len(box.ch); n > 0; n-- {
			select {
			case s := <-box.ch:
				// a fresh spare goes back unless the client closed meanwhile
				if time.Since(s.at) >= p.sessionTTL/3 || !box.put(s) {
					dropSpare(s)
				}
			default:
			}
		}
		for len(box.ch) < cap(box.ch) {
			for i := 0; i < 40; i++ {
				if box.stop.Load() {
					return
				}
				time.Sleep(50 * time.Millisecond)
			}
			if box.stop.Load() {
				return
			}
			storage, err := c.shared()
			if err != nil {
				return
			}
			storage = sessionStorage(storage)
			slots, ok := storage.(slotStore)
			if !ok {
				storage.Close()
				return
			}
			session, err := newSessionID()
			if err != nil {
				storage.Close()
				return
			}
			ctx, cancel := context.WithTimeout(box.ctx, 30*time.Second)
			r, err := makeRing(ctx, slots, session, p)
			cancel()
			if err != nil {
				dropSpare(spareRing{storage: storage, session: session})
				return
			}
			spare := spareRing{storage: storage, session: session, ring: r, at: time.Now()}
			if !box.put(spare) {
				// the client closed while the ring was made
				dropSpare(spare)
				return
			}
		}
		time.AfterFunc(p.sessionTTL/4, func() {
			if !box.stop.Load() && time.Since(time.Unix(0, box.last.Load())) < spareIdleStop {
				c.fillSpares(p)
			}
		})
	}()
}

// Dial opens a session. The session does not depend on ctx once it is open.
func (c *Client) Dial(ctx context.Context) (net.Conn, error) {
	config := c.config

	p := paramsFromConfig(config)
	var err error

	spare, warm := c.takeSpare(p)
	storage, session, r := spare.storage, spare.session, spare.ring
	if !warm {
		storage, err = c.shared()
		if err != nil {
			return nil, err
		}
		storage = sessionStorage(storage)

		session, err = newSessionID()
		if err != nil {
			storage.Close()
			return nil, err
		}
	}

	p = paramsForStorage(config, storage)

	slots, ok := storage.(slotStore)
	if ok && !warm {
		if r, err = makeRing(ctx, slots, session, p); err != nil {
			ok = false
			logWarningInner(ctx, err, "failed to make the slots of session ", session, ", it goes in segments")
		}
	}

	if ok {
		// A health check does not keep the spare rings warm: one every few
		// minutes would refresh them forever on a client nobody uses.
		if !C.IsHealthCheck(ctx) {
			c.warmSpares(p)
		}
		logInfo(ctx, "opened session ", session, " in ", len(r.Up.Slots), " slots")
		conn := newSlotConn(context.Background(), slots, r.Up, r.Down, p, nil, func() {
			storage.Close()
		})
		writer := conn.writer.(*slotWriter)
		writer.first = make(chan []byte, 1)
		go func() {
			var first []byte
			select {
			case first = <-writer.first:
			case <-time.After(25 * time.Millisecond):
			}
			announce, _ := json.Marshal(r)
			if len(first) > 0 && len(first) <= slotInlineLimit {
				withFirst := r
				withFirst.First = first
				if encoded, err := json.Marshal(withFirst); err == nil && len(encoded) <= driveInlineLimit {
					announce = encoded
				}
			}
			// An announce failure surfaces as a connection error on the next Write/Read.
			if err := storage.Put(context.Background(), announceName(session, time.Now()), announce); err != nil {
				err = newError("failed to announce session ", session).Base(err)
				writer.fail(err)
				conn.reader.(*slotReader).setErr(err)
			}
		}()
		return conn, nil
	}

	if err := storage.Put(ctx, announceName(session, time.Now()), nil); err != nil {
		storage.Close()
		return nil, newError("failed to announce session ", session).Base(err)
	}
	logInfo(ctx, "opened session ", session)
	return newConn(context.Background(), storage,
		uplinkPrefix(session), downlinkPrefix(session), p, func() {
			storage.Close()
		}), nil
}

type Listener struct {
	ctx     context.Context
	cancel  context.CancelFunc
	storage Storage
	addConn func(net.Conn)
	params

	mu             sync.Mutex
	active         map[string]bool
	handled        map[string]time.Time
	idleSince      map[string]time.Time
	announceWarned map[string]bool
	firstSeen      map[string]time.Time
}

// Listen serves the sessions that clients announce to the storage of a Config
// that went through Normalize; addConn takes each new session and must not
// block. There is no socket: an address has no meaning for this transport.
func Listen(config *Config, dialer *Dialer, addConn func(net.Conn)) (*Listener, error) {
	storage, err := newStorage(config, dialer)
	if err != nil {
		return nil, err
	}

	listenerCtx, cancel := context.WithCancel(context.Background())
	listener := &Listener{
		ctx:            listenerCtx,
		cancel:         cancel,
		storage:        storage,
		addConn:        addConn,
		params:         paramsForStorage(config, storage),
		active:         make(map[string]bool),
		handled:        make(map[string]time.Time),
		idleSince:      make(map[string]time.Time),
		announceWarned: make(map[string]bool),
		firstSeen:      make(map[string]time.Time),
	}

	go listener.acceptLoop(listenerCtx)
	go listener.collectLoop(listenerCtx)

	return listener, nil
}

func (l *Listener) acceptLoop(logCtx context.Context) {
	delay := l.minPollInterval
	active := time.Now()
	for {
		accepted, err := l.acceptPending(logCtx)
		if err != nil && !isAuthError(err) && l.ctx.Err() == nil {
			logWarningInner(logCtx, err, "failed to list sessions")
		}

		switch {
		case accepted:
			active = time.Now()
			delay = l.minPollInterval
		case time.Since(active) < l.eagerWindow:
			delay = l.minPollInterval
		default:
			delay *= 2
			if delay > l.maxPollInterval {
				delay = l.maxPollInterval
			}
		}

		select {
		case <-l.ctx.Done():
			return
		case <-time.After(delay):
		}
	}
}

func (l *Listener) acceptPending(logCtx context.Context) (bool, error) {
	sessions, err := l.storage.List(l.ctx, sessionsDir)
	if err != nil {
		return false, err
	}

	accepted := false
	l.mu.Lock()
	if l.firstSeen == nil {
		l.firstSeen = make(map[string]time.Time)
	}
	now := time.Now()
	listedEntries := make(map[string]bool, len(sessions))
	for _, listed := range sessions {
		listedEntries[listed.Name] = true
		if _, seen := l.firstSeen[listed.Name]; !seen {
			l.firstSeen[listed.Name] = now
		}
	}
	for entry := range l.firstSeen {
		if !listedEntries[entry] {
			delete(l.firstSeen, entry)
		}
	}
	l.mu.Unlock()

	for _, listed := range sessions {
		entry := listed.Name
		full := sessionsDir + "/" + entry

		session, _, ok := parseAnnounce(entry)
		if !ok {
			go l.drop(full)
			continue
		}
		l.mu.Lock()
		age := now.Sub(l.firstSeen[entry])
		l.mu.Unlock()
		if age > l.sessionTTL {
			logInfo(logCtx, "dropping the stale announcement of session ", session)
			go l.drop(full)
			l.mu.Lock()
			protected := l.active[session] || !l.handled[session].IsZero()
			l.mu.Unlock()
			if !protected {
				go l.drop(sessionPrefix(session))
			}
			continue
		}
		if !l.claim(session) {
			continue
		}
		announce := listed.Inline
		if len(announce) == 0 {
			if _, ok := sessionStorage(l.storage).(slotStore); ok {
				announce, err = l.storage.Get(context.WithValue(l.ctx, maxBodyKey{}, int64(driveMaxAnnounce)), full)
				if err != nil {
					l.mu.Lock()
					delete(l.active, session)
					delete(l.handled, session)
					warn := !l.announceWarned[session]
					l.announceWarned[session] = true
					l.mu.Unlock()
					if warn {
						logWarningInner(logCtx, err, "failed to read the announcement of session ", session)
					}
					continue
				}
			}
		}
		go l.drop(full)
		accepted = true
		l.addConn(l.newSessionConn(logCtx, session, announce))
	}
	return accepted, nil
}

func (l *Listener) drop(name string) {
	l.storage.Delete(l.ctx, name)
}

func (l *Listener) claim(session string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.active[session] || !l.handled[session].IsZero() {
		return false
	}
	l.active[session] = true
	l.handled[session] = time.Now()
	return true
}

// newSessionConn takes a session in the slots that its announcement has, or
// in segments if it has none
func (l *Listener) newSessionConn(logCtx context.Context, session string, announce []byte) *Conn {
	storage := sessionStorage(l.storage)
	onClose := func() {
		storage.Close()
		l.mu.Lock()
		delete(l.active, session)
		l.mu.Unlock()
	}
	if slots, ok := storage.(slotStore); ok {
		if r, ok := decodeRing(announce); ok {
			logInfo(logCtx, "accepted session ", session, " in ", len(r.Down.Slots), " slots")
			return newSlotConn(l.ctx, slots, r.Down, r.Up, l.params, r.First, onClose)
		}
	}
	logInfo(logCtx, "accepted session ", session)
	return newConn(l.ctx, storage, downlinkPrefix(session), uplinkPrefix(session), l.params, onClose)
}

func (l *Listener) collectLoop(logCtx context.Context) {
	interval := l.sessionTTL / 2
	for {
		select {
		case <-l.ctx.Done():
			return
		case <-time.After(interval):
		}
		if err := l.collect(); err != nil {
			logWarningInner(logCtx, err, "failed to collect abandoned sessions")
		}
	}
}

func (l *Listener) collect() error {
	sessions, err := l.storage.List(l.ctx, streamsDir)
	if err != nil {
		return err
	}

	now := time.Now()
	var expired []string

	l.mu.Lock()
	present := make(map[string]bool, len(sessions))
	for _, listed := range sessions {
		session := listed.Name
		present[session] = true
		if l.active[session] {
			delete(l.idleSince, session)
			continue
		}
		since, seen := l.idleSince[session]
		if !seen {
			l.idleSince[session] = now
			continue
		}
		if now.Sub(since) >= l.sessionTTL {
			expired = append(expired, session)
			delete(l.idleSince, session)
		}
	}
	for session := range l.idleSince {
		if !present[session] {
			delete(l.idleSince, session)
		}
	}
	for session, at := range l.handled {
		if !l.active[session] && now.Sub(at) >= l.sessionTTL {
			delete(l.handled, session)
		}
	}
	l.mu.Unlock()

	var first error
	for _, session := range expired {
		if err := l.storage.Delete(l.ctx, sessionPrefix(session)); err != nil && first == nil {
			first = err
		}
	}
	return first
}

func (l *Listener) Close() error {
	l.cancel()
	return l.storage.Close()
}
