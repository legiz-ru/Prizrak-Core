package sockopt

import (
	"net"
	"os"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func dialWith(t *testing.T, o *Options) *net.TCPConn {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		c, err := ln.Accept()
		if err == nil {
			t.Cleanup(func() { c.Close() })
		}
	}()
	c, err := (&net.Dialer{ControlContext: o.Control}).Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	o.AfterDial(c)
	return c.(*net.TCPConn)
}

func getInt(t *testing.T, c *net.TCPConn, level, opt int) int {
	t.Helper()
	raw, _ := c.SyscallConn()
	var v int
	var err error
	_ = raw.Control(func(fd uintptr) { v, err = unix.GetsockoptInt(int(fd), level, opt) })
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func getString(t *testing.T, c *net.TCPConn, level, opt int) string {
	t.Helper()
	raw, _ := c.SyscallConn()
	var v string
	var err error
	_ = raw.Control(func(fd uintptr) { v, err = unix.GetsockoptString(int(fd), level, opt) })
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimRight(v, "\x00")
}

func TestOptionsApplied(t *testing.T) {
	congestion := "reno"
	if b, err := os.ReadFile("/proc/sys/net/ipv4/tcp_available_congestion_control"); err == nil && strings.Contains(string(b), "bbr") {
		congestion = "bbr"
	}
	nodelay, err := ParseCustom("", "", "", "1", "int", "0") // TCP_NODELAY, which Go turns on after connect
	if err != nil {
		t.Fatal(err)
	}
	c := dialWith(t, &Options{
		Name:              "test",
		TCPCongestion:     congestion,
		TCPUserTimeout:    10000,
		KeepAliveIdle:     300,
		KeepAliveInterval: 60,
		Custom:            []Custom{nodelay},
	})
	if got := getString(t, c, unix.IPPROTO_TCP, unix.TCP_CONGESTION); got != congestion {
		t.Fatalf("congestion %q, want %q", got, congestion)
	}
	if got := getInt(t, c, unix.IPPROTO_TCP, unix.TCP_USER_TIMEOUT); got != 10000 {
		t.Fatalf("user timeout %d", got)
	}
	if getInt(t, c, unix.SOL_SOCKET, unix.SO_KEEPALIVE) != 1 || getInt(t, c, unix.IPPROTO_TCP, unix.TCP_KEEPIDLE) != 300 {
		t.Fatal("keep-alive idle not applied")
	}
	if got := getInt(t, c, unix.IPPROTO_TCP, unix.TCP_NODELAY); got != 0 {
		t.Fatalf("custom TCP_NODELAY %d, want 0", got)
	}
}

func TestUnsupportedOptionDoesNotFail(t *testing.T) {
	bad, _ := ParseCustom("", "", "", "9999", "int", "1")
	other, _ := ParseCustom("windows", "", "", "1", "int", "0")
	c := dialWith(t, &Options{Name: "test", TCPCongestion: "no-such-algorithm", Custom: []Custom{bad, other}})
	if got := getInt(t, c, unix.IPPROTO_TCP, unix.TCP_NODELAY); got != 1 {
		t.Fatalf("an option for windows was applied on linux (TCP_NODELAY %d)", got)
	}
}

func TestKeepAliveDisabled(t *testing.T) {
	c := dialWith(t, &Options{Name: "test", KeepAliveIdle: -1})
	if getInt(t, c, unix.SOL_SOCKET, unix.SO_KEEPALIVE) != 0 {
		t.Fatal("keep-alive still on")
	}
}

func TestParseCustom(t *testing.T) {
	c, err := ParseCustom("Linux", "tcp", "0x6", "13", "str", "bbr")
	if err != nil || c.Level != 6 || c.Opt != 13 || c.Int || c.StrVal != "bbr" || c.System != "linux" {
		t.Fatal(c, err)
	}
	for _, args := range [][6]string{
		{"", "", "", "", "int", "1"},
		{"", "", "x", "1", "int", "1"},
		{"", "", "", "1", "int", "y"},
		{"", "", "", "1", "bytes", "1"},
	} {
		if _, err := ParseCustom(args[0], args[1], args[2], args[3], args[4], args[5]); err == nil {
			t.Fatalf("%v accepted", args)
		}
	}
}
