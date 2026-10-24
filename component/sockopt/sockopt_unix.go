//go:build unix && !linux

package sockopt

import (
	"errors"

	"golang.org/x/sys/unix"
)

var errLinuxOnly = errors.New("only supported on Linux and Android")

func setCongestion(fd uintptr, name string) error { return errLinuxOnly }

func setUserTimeout(fd uintptr, ms int) error { return errLinuxOnly }

func setInt(fd uintptr, level, opt, value int) error {
	return unix.SetsockoptInt(int(fd), level, opt, value)
}

func setString(fd uintptr, level, opt int, value string) error {
	return unix.SetsockoptString(int(fd), level, opt, value)
}
