//go:build !linux && !darwin

package fragment

// Windows needs administrator rights for the TCP statistics sing-box reads
// there; this port does not use them and falls back to the delay.
func unackedBytes(fd uintptr) (int, bool) { return 0, false }
