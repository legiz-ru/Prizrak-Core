//go:build !linux

package xhttp

import (
	"net"
	"syscall"
)

func rawTCP(net.Conn) syscall.RawConn { return nil }

func readTCPStats(syscall.RawConn) (tcpStats, bool) { return tcpStats{}, false }
