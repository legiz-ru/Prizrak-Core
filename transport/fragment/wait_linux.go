package fragment

import "golang.org/x/sys/unix"

func unackedBytes(fd uintptr) (int, bool) {
	info, err := unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO)
	if err != nil {
		return 0, false
	}
	return int(info.Unacked), true
}
