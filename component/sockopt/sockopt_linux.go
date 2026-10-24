package sockopt

import "golang.org/x/sys/unix"

func setCongestion(fd uintptr, name string) error {
	return unix.SetsockoptString(int(fd), unix.IPPROTO_TCP, unix.TCP_CONGESTION, name)
}

func setUserTimeout(fd uintptr, ms int) error {
	return unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_USER_TIMEOUT, ms)
}

func setInt(fd uintptr, level, opt, value int) error {
	return unix.SetsockoptInt(int(fd), level, opt, value)
}

func setString(fd uintptr, level, opt int, value string) error {
	return unix.SetsockoptString(int(fd), level, opt, value)
}
