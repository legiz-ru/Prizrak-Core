package outbound

import (
	"sync"

	"github.com/metacubex/mihomo/log"

	"github.com/metacubex/quic-go"
	"github.com/metacubex/tls"
)

// quicSessionCacheSize is the number of server names a proxy keeps a TLS
// session ticket for. A proxy talks to one or two (XHTTP's download side).
const quicSessionCacheSize = 4

// quicSessionCaches holds the TLS session tickets of a proxy's QUIC
// connections (enable-session-resumption), one cache per server address, so that a
// ticket of one server is not offered to another with the same SNI. quic-go
// resumes with a ticket of the cache; with DialEarly and a ticket that allows
// it, the HTTP/3 SETTINGS go in 0-RTT. Requests wait for the handshake (the
// HTTP/3 client sends only GET_0RTT and HEAD_0RTT before it), so nothing a
// replay could repeat goes in 0-RTT. With the browser's QUIC handshake, the
// default, a ticket is used once and the resumed hello is that of the browser
// of client-fingerprint; with disable-chrome-parrot, as Go's crypto/tls does.
type quicSessionCaches struct {
	caches sync.Map // server address -> tls.ClientSessionCache
}

func (c *quicSessionCaches) get(addr string) tls.ClientSessionCache {
	if cache, ok := c.caches.Load(addr); ok {
		return cache.(tls.ClientSessionCache)
	}
	cache, _ := c.caches.LoadOrStore(addr, tls.NewLRUClientSessionCache(quicSessionCacheSize))
	return cache.(tls.ClientSessionCache)
}

// logQUICResumption logs, at debug, whether the TLS session of a QUIC
// connection was resumed and whether the server took 0-RTT.
func logQUICResumption(proxy string, conn *quic.Conn) {
	go func() {
		select {
		case <-conn.HandshakeComplete():
		case <-conn.Context().Done():
			return
		}
		state := conn.ConnectionState()
		log.Debugln("[QUIC] %s: TLS session resumed: %t, 0-RTT accepted: %t", proxy, state.TLS.DidResume, state.Used0RTT)
	}()
}
