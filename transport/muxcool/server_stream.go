package muxcool

import (
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	M "github.com/metacubex/sing/common/metadata"
)

const serverStreamQueueSize = 16

type serverStreamMessage struct {
	payload       []byte
	payloadPooled bool
}

func (m *serverStreamMessage) release() {
	releasePooledPayload(m.payload, m.payloadPooled)
	m.payload = nil
	m.payloadPooled = false
}

type serverStream struct {
	carrier     *serverCarrier
	id          uint16
	destination M.Socksaddr
	client      net.Conn
	peer        net.Conn
	input       chan serverStreamMessage
	done        chan struct{}
	closeOnce   sync.Once
	// progress is when the target last took a message of the stream, in
	// Unix nanoseconds.
	progress atomic.Int64
}

func newServerStream(carrier *serverCarrier, id uint16, destination M.Socksaddr) *serverStream {
	client, peer := net.Pipe()
	s := &serverStream{
		carrier:     carrier,
		id:          id,
		destination: destination,
		client:      client,
		peer:        peer,
		input:       make(chan serverStreamMessage, serverStreamQueueSize),
		done:        make(chan struct{}),
	}
	s.progress.Store(time.Now().UnixNano())
	return s
}

func (s *serverStream) start() {
	go s.writeInput()
	go s.readOutput()
	go func() {
		metadata := M.Metadata{Source: s.carrier.metadata.Source, Destination: s.destination}
		if err := s.carrier.handler.NewConnection(s.carrier.ctx, s.client, metadata); err != nil {
			s.finish(err, true)
		}
	}()
}

func (s *serverStream) deliverDecodedFrame(frame decodedFrame) error {
	if frame.Option&OptionData == 0 || len(frame.Payload) == 0 {
		frame.releasePayload()
		return nil
	}
	message := serverStreamMessage{payload: frame.Payload, payloadPooled: frame.payloadPooled}
	select {
	case s.input <- message:
		return nil
	case <-s.done:
		message.release()
		return net.ErrClosed
	default:
	}
	// Blocks the carrier's read loop while the stream drains, as Xray does: a
	// TCP stream must not lose a frame for writing faster than the target reads.
	// As connIdle does in Xray, a target that takes nothing for the idle
	// timeout ends the wait and its stream, so it cannot hold the carrier.
	idle := s.carrier.runtime.options.StreamIdleTimeout
	waitStart := time.Now().UnixNano()
	timer := time.NewTimer(idle)
	defer timer.Stop()
	for {
		select {
		case s.input <- message:
			return nil
		case <-s.done:
			message.release()
			return net.ErrClosed
		case <-timer.C:
			// idle since the target last took a message or, if that was
			// before, since the carrier began to wait for it
			last := s.progress.Load()
			if last < waitStart {
				last = waitStart
			}
			if since := time.Since(time.Unix(0, last)); since < idle {
				timer.Reset(idle - since)
				continue
			}
			message.release()
			return ErrStreamStalled
		}
	}
}

func (s *serverStream) writeInput() {
	for {
		select {
		case message := <-s.input:
			err := writeFull(s.peer, message.payload)
			message.release()
			if err != nil {
				s.finish(err, true)
				return
			}
			s.progress.Store(time.Now().UnixNano())
		case <-s.done:
			s.releaseQueued()
			return
		}
	}
}

func (s *serverStream) readOutput() {
	buffer := sessionBufferPool.Get().(*[MaxPayloadSize]byte)
	defer sessionBufferPool.Put(buffer)
	for {
		n, err := s.peer.Read(buffer[:])
		if n > 0 {
			writeErr := s.carrier.writeFrame(Frame{
				SessionID: s.id,
				Status:    StatusKeep,
				Option:    OptionData,
				Payload:   buffer[:n],
			})
			if writeErr != nil {
				s.finish(writeErr, false)
				return
			}
		}
		if err != nil {
			s.finish(nil, errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed))
			return
		}
	}
}

func (s *serverStream) finish(cause error, sendEnd bool) {
	s.closeOnce.Do(func() {
		close(s.done)
		_ = s.peer.Close()
		_ = s.client.Close()
		s.carrier.removeSession(s.id, s)
		if sendEnd {
			option := Option(0)
			if cause != nil && !errors.Is(cause, io.EOF) && !errors.Is(cause, net.ErrClosed) {
				option = OptionError
			}
			_ = s.carrier.writeFrame(Frame{SessionID: s.id, Status: StatusEnd, Option: option})
		}
	})
}

func (s *serverStream) releaseQueued() {
	for {
		select {
		case message := <-s.input:
			message.release()
		default:
			return
		}
	}
}

var _ serverSession = (*serverStream)(nil)
