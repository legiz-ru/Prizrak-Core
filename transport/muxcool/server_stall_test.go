package muxcool

import (
	"bytes"
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
)

// drainTestCarrier reads what the server sends on carrier and reports the End
// frames, so that the server never blocks writing to the pipe.
func drainTestCarrier(carrier net.Conn) <-chan Frame {
	ends := make(chan Frame, 64)
	go func() {
		for {
			frame, err := DecodeFrame(carrier)
			if err != nil {
				return
			}
			if frame.Status == StatusEnd {
				select {
				case ends <- frame:
				default:
				}
			}
		}
	}()
	return ends
}

// Stream 9's target never reads. The carrier waits to hand it data no
// longer than the stream idle timeout, then ends the stream and goes on:
// stream 11, opened after it, gets its data, and closing the client stops
// Serve (checked by serveTestCarrier). Found by an independent review: the
// wait had no bound, so one stuck target froze the whole carrier.
func TestServerStalledStreamDoesNotHoldCarrier(t *testing.T) {
	runtime := NewServerRuntime(ServerOptions{XUDPIdleTimeout: time.Hour, StreamIdleTimeout: 200 * time.Millisecond})
	t.Cleanup(func() { _ = runtime.Close() })

	got11 := make(chan struct{}, 1)
	block := make(chan struct{})
	t.Cleanup(func() { close(block) })
	handler := testServerHandler{
		tcp: func(_ context.Context, conn net.Conn, md M.Metadata) error {
			if md.Destination.Port == 1 {
				<-block // a target that does not read
				return errors.New("done")
			}
			buf := make([]byte, 16)
			if _, err := conn.Read(buf); err == nil {
				got11 <- struct{}{}
			}
			<-block
			return nil
		},
		udp: func(context.Context, N.PacketConn, M.Metadata) error { return errors.New("unexpected UDP") },
	}
	carrier := serveTestCarrier(t, runtime, handler)
	ends := drainTestCarrier(carrier)

	go func() {
		payload := bytes.Repeat([]byte{7}, MaxPayloadSize)
		write := func(f Frame) bool {
			raw, err := EncodeFrame(f)
			if err != nil {
				return false
			}
			_, err = carrier.Write(raw)
			return err == nil
		}
		write(Frame{SessionID: 9, Status: StatusNew, Option: OptionData, Network: NetworkTCP, Destination: "a.example", Port: 1, Payload: payload})
		for i := 0; i < 40; i++ {
			if !write(Frame{SessionID: 9, Status: StatusKeep, Option: OptionData, Payload: payload}) {
				return
			}
		}
		write(Frame{SessionID: 9, Status: StatusEnd})
		write(Frame{SessionID: 11, Status: StatusNew, Option: OptionData, Network: NetworkTCP, Destination: "b.example", Port: 2, Payload: []byte("hello")})
	}()

	select {
	case <-got11:
	case <-time.After(3 * time.Second):
		t.Fatal("stream 11 got nothing: the stalled stream 9 held the carrier")
	}
	select {
	case end := <-ends:
		if end.SessionID != 9 || end.Option&OptionError == 0 {
			t.Fatalf("first End = session %d option %d, want session 9 with an error", end.SessionID, end.Option)
		}
	case <-time.After(time.Second):
		t.Fatal("the stalled stream was not ended")
	}
}

// A target that reads slowly but steadily is not taken for a stalled one,
// however long the carrier waits for it in all.
func TestServerSlowStreamIsNotStalled(t *testing.T) {
	runtime := NewServerRuntime(ServerOptions{XUDPIdleTimeout: time.Hour, StreamIdleTimeout: 300 * time.Millisecond})
	t.Cleanup(func() { _ = runtime.Close() })

	const frames = 40
	var received sync.WaitGroup
	received.Add(1)
	handler := testServerHandler{
		tcp: func(_ context.Context, conn net.Conn, md M.Metadata) error {
			defer received.Done()
			buf := make([]byte, MaxPayloadSize)
			total := 0
			for total < (frames+1)*MaxPayloadSize {
				n, err := conn.Read(buf)
				if err != nil {
					return err
				}
				total += n
				time.Sleep(20 * time.Millisecond)
			}
			return nil
		},
		udp: func(context.Context, N.PacketConn, M.Metadata) error { return errors.New("unexpected UDP") },
	}
	carrier := serveTestCarrier(t, runtime, handler)
	ends := drainTestCarrier(carrier)

	payload := bytes.Repeat([]byte{7}, MaxPayloadSize)
	writeTestFrame(t, carrier, Frame{SessionID: 5, Status: StatusNew, Option: OptionData, Network: NetworkTCP, Destination: "slow.example", Port: 1, Payload: payload})
	for i := 0; i < frames; i++ {
		writeTestFrame(t, carrier, Frame{SessionID: 5, Status: StatusKeep, Option: OptionData, Payload: payload})
	}
	done := make(chan struct{})
	go func() {
		received.Wait()
		close(done)
	}()
	select {
	case <-done:
	case end := <-ends:
		t.Fatalf("the slow stream was ended (option %d)", end.Option)
	case <-time.After(10 * time.Second):
		t.Fatal("the slow target did not get all its data")
	}
}
