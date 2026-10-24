package fragment

import "golang.org/x/sys/unix"

// SO_NWRITE is the number of bytes in the send buffer, sent or not, that the
// peer has not acknowledged yet.
func unackedBytes(fd uintptr) (int, bool) {
	n, err := unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_NWRITE)
	if err != nil {
		return 0, false
	}
	return n, true
}
