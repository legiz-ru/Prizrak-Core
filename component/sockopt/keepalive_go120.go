//go:build !go1.23

package sockopt

import (
	"net"
	"time"
)

// Before Go 1.23 one period sets both the idle time and the probe interval.
func setKeepAlive(tcp *net.TCPConn, idle, interval int) error {
	if idle < 0 || interval < 0 {
		return tcp.SetKeepAlive(false)
	}
	if err := tcp.SetKeepAlive(true); err != nil {
		return err
	}
	period := idle
	if period == 0 {
		period = interval
	}
	return tcp.SetKeepAlivePeriod(time.Duration(period) * time.Second)
}
