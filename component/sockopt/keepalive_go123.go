//go:build go1.23

package sockopt

import (
	"net"
	"time"
)

func setKeepAlive(tcp *net.TCPConn, idle, interval int) error {
	if idle < 0 || interval < 0 {
		return tcp.SetKeepAlive(false)
	}
	// zero picks Go's default, a negative Count leaves the system's
	return tcp.SetKeepAliveConfig(net.KeepAliveConfig{
		Enable:   true,
		Idle:     time.Duration(idle) * time.Second,
		Interval: time.Duration(interval) * time.Second,
		Count:    -1,
	})
}
