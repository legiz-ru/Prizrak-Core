// Ported from Xray-core v26.11.9 transport/internet/splithttp/mux.go
// (https://github.com/XTLS/Xray-core), which is licensed under the Mozilla
// Public License 2.0; this file stays under MPL-2.0.
// SPDX-License-Identifier: MPL-2.0

package xdrive

import (
	"io"
	"math"
	"sync/atomic"
	"time"

	"github.com/metacubex/randv2"
)

type xmuxConn interface {
	IsClosed() bool
}

type xmuxClient struct {
	conn         xmuxConn
	running      atomic.Int32
	leftUsage    int32
	leftRequests atomic.Int32
	unreusableAt time.Time
	notUsed      atomic.Bool
}

func (c *xmuxClient) addRunning() {
	c.running.Add(1)
}

func (c *xmuxClient) doneRunning() {
	c.running.Add(-1)
	c.maybeClose()
}

// maybeClose closes the conn if it is not used and has no running requests.
func (c *xmuxClient) maybeClose() {
	if c.notUsed.Load() && c.running.Load() <= 0 {
		if closer, ok := c.conn.(io.Closer); ok {
			_ = closer.Close()
		}
	}
}

// xmuxManager is the XmuxManager of Xray-core, for HTTP clients that a
// session keeps for as long as it can.
type xmuxManager struct {
	config      XmuxConfig
	concurrency int32
	connections int32
	newConn     func() xmuxConn
	clients     []*xmuxClient
}

// randRange is RangeConfig.rand of Xray-core, from inclusive and to exclusive
// unless they are equal or next to each other. Like crypto.RandBetween of
// Xray-core it counts in int64, so that no range of int32 overflows.
func randRange(r *Range) int32 {
	if r == nil {
		return 0
	}
	from, to := int64(r.From), int64(r.To)
	if from > to {
		from, to = to, from
	}
	if d := to - from; d == 0 || d == 1 {
		return int32(from)
	}
	return int32(from + randv2.Int64N(to-from))
}

func newXmuxManager(config XmuxConfig, newConn func() xmuxConn) *xmuxManager {
	return &xmuxManager{
		config:      config,
		concurrency: randRange(config.MaxConcurrency),
		connections: randRange(config.MaxConnections),
		newConn:     newConn,
	}
}

func (m *xmuxManager) newClient() *xmuxClient {
	client := &xmuxClient{
		conn:      m.newConn(),
		leftUsage: -1,
	}
	if x := randRange(m.config.CMaxReuseTimes); x > 0 {
		client.leftUsage = x - 1
	}
	client.leftRequests.Store(math.MaxInt32)
	if x := randRange(m.config.HMaxRequestTimes); x > 0 {
		client.leftRequests.Store(x)
	}
	if x := randRange(m.config.HMaxReusableSecs); x > 0 {
		client.unreusableAt = time.Now().Add(time.Duration(x) * time.Second)
	}
	m.clients = append(m.clients, client)
	return client
}

func (m *xmuxManager) getClient() *xmuxClient {
	for i := 0; i < len(m.clients); {
		client := m.clients[i]
		if client.conn.IsClosed() ||
			client.leftUsage == 0 ||
			client.leftRequests.Load() <= 0 ||
			(!client.unreusableAt.IsZero() && time.Now().After(client.unreusableAt)) {
			client.notUsed.Store(true)
			client.maybeClose()
			m.clients = append(m.clients[:i], m.clients[i+1:]...)
		} else {
			i++
		}
	}

	if len(m.clients) == 0 {
		return m.newClient()
	}
	if m.connections > 0 && len(m.clients) < int(m.connections) {
		return m.newClient()
	}

	clients := make([]*xmuxClient, 0, len(m.clients))
	if m.concurrency > 0 {
		for _, client := range m.clients {
			if client.running.Load() < m.concurrency {
				clients = append(clients, client)
			}
		}
	} else {
		clients = m.clients
	}
	if len(clients) == 0 {
		return m.newClient()
	}

	client := clients[randv2.IntN(len(clients))]
	if client.leftUsage > 0 {
		client.leftUsage--
	}
	return client
}
