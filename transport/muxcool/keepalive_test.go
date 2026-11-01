package muxcool

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
)

type keepAliveTestConn struct {
	net.Conn
	idle atomic.Int64
}

func (c *keepAliveTestConn) MuxKeepAlive() (int32, int32)      { return 1, 1 }
func (c *keepAliveTestConn) MuxKeepAliveBytes() (int32, int32) { return 8, 16 }
func (c *keepAliveTestConn) DownlinkIdle() time.Duration       { return time.Duration(c.idle.Load()) }

type upstreamTestConn struct {
	net.Conn
	upstream net.Conn
}

func (c *upstreamTestConn) Upstream() any { return c.upstream }

type nopServerHandler struct{}

func (nopServerHandler) NewConnection(context.Context, net.Conn, M.Metadata) error { return nil }
func (nopServerHandler) NewPacketConnection(context.Context, N.PacketConn, M.Metadata) error {
	return nil
}

// A carrier whose connection, under any wrapper, asks for KeepAlive pokes gets
// a padded KeepAlive frame once its downlink has been idle that long, and
// none while it carries data.
func TestServerCarrierPokesIdleDownlink(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	conn := &keepAliveTestConn{Conn: server}
	conn.idle.Store(int64(time.Hour))
	runtime := NewServerRuntime(ServerOptions{})
	defer runtime.Close()
	go func() {
		_ = runtime.Serve(context.Background(), &upstreamTestConn{Conn: conn, upstream: conn}, M.Metadata{}, nopServerHandler{})
	}()

	_ = client.SetReadDeadline(time.Now().Add(3 * time.Second))
	frame, err := DecodeFrame(client)
	if err != nil {
		t.Fatalf("no KeepAlive frame: %v", err)
	}
	if frame.Status != StatusKeepAlive || frame.Option != OptionData || len(frame.Payload) < 8 || len(frame.Payload) > 16 {
		t.Fatalf("got status %d option %d with %d bytes, want a KeepAlive with 8-16 bytes of padding", frame.Status, frame.Option, len(frame.Payload))
	}

	// A downlink that carries data is left alone.
	conn.idle.Store(0)
	_ = client.SetReadDeadline(time.Now().Add(2500 * time.Millisecond))
	if frame, err := DecodeFrame(client); err == nil {
		t.Fatalf("a busy downlink got a frame with status %d", frame.Status)
	}
}

func TestServerCarrierWithoutKeepAliveStaysSilent(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	runtime := NewServerRuntime(ServerOptions{})
	defer runtime.Close()
	go func() { _ = runtime.Serve(context.Background(), server, M.Metadata{}, nopServerHandler{}) }()

	_ = client.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
	if frame, err := DecodeFrame(client); err == nil {
		t.Fatalf("got a frame with status %d", frame.Status)
	}
}
