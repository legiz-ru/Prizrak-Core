package fragment

import (
	"context"
	"net"
	"time"
)

const (
	ackPollInterval = 10 * time.Millisecond
	ackMaxWait      = 3 * time.Second
	// An ACK within this time comes from something next to us (a transparent
	// proxy, a local middlebox), not from the server, so it proves nothing
	// and the fallback delay is used, as in sing-box.
	ackTooFast = 20 * time.Millisecond
)

// waitAck waits until the kernel has no unacknowledged bytes left on tcp.
// Where that can't be read it waits for the fallback delay instead.
func waitAck(ctx context.Context, tcp *net.TCPConn, fallback time.Duration) {
	if tcp == nil {
		sleep(ctx, fallback)
		return
	}
	raw, err := tcp.SyscallConn()
	if err != nil {
		sleep(ctx, fallback)
		return
	}
	start := time.Now()
	for {
		var pending int
		var supported bool
		_ = raw.Control(func(fd uintptr) {
			pending, supported = unackedBytes(fd)
		})
		if !supported {
			sleep(ctx, fallback)
			return
		}
		if pending == 0 {
			if time.Since(start) <= ackTooFast {
				sleep(ctx, fallback)
			}
			return
		}
		if ctx.Err() != nil || time.Since(start) > ackMaxWait {
			return
		}
		sleep(ctx, ackPollInterval)
	}
}
