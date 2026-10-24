package sockopt

import (
	"errors"

	"golang.org/x/sys/windows"
)

var (
	errLinuxOnly   = errors.New("only supported on Linux and Android")
	errNoStringOpt = errors.New("string values are not supported on Windows")
)

func setCongestion(fd uintptr, name string) error { return errLinuxOnly }

func setUserTimeout(fd uintptr, ms int) error { return errLinuxOnly }

func setInt(fd uintptr, level, opt, value int) error {
	return windows.SetsockoptInt(windows.Handle(fd), level, opt, value)
}

func setString(fd uintptr, level, opt int, value string) error { return errNoStringOpt }
