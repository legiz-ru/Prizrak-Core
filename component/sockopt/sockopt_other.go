//go:build !unix && !windows

package sockopt

import "errors"

var errUnsupported = errors.New("socket options are not supported on this system")

func setCongestion(fd uintptr, name string) error { return errUnsupported }

func setUserTimeout(fd uintptr, ms int) error { return errUnsupported }

func setInt(fd uintptr, level, opt, value int) error { return errUnsupported }

func setString(fd uintptr, level, opt int, value string) error { return errUnsupported }
