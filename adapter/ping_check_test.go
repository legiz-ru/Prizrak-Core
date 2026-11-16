package adapter

import (
	"errors"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/pingconfig"
)

// The ping-config log line says first whether the check passed, then what
// decided it, the destination's answer, then the delay, which is the url's.
func TestPingCheckLine(t *testing.T) {
	const url = "https://www.gstatic.com/generate_204"
	const dest = "https://speed.cloudflare.com/__down?bytes=51200"
	get := &pingconfig.Profile{URL: url, Destination: dest, Method: pingconfig.MethodGET}
	head := &pingconfig.Profile{URL: url, Destination: url, Method: pingconfig.MethodHEAD}
	timeout := errors.New("context deadline exceeded")
	for _, tc := range []struct {
		name                  string
		profile               *pingconfig.Profile
		check                 destinationCheck
		err                   error
		passed, online, alive bool
		want                  string
	}{
		{
			name: "passed", profile: get, passed: true, alive: true,
			check: destinationCheck{delay: 212, status: 204, asked: true, bytes: 51200, elapsed: 840 * time.Millisecond},
			want:  "Ping-config passed, proxy: NL, destination: GET " + dest + " answered 51200 bytes in 840 ms, delay: 212 ms from url " + url + ", alive: true",
		},
		{
			name: "destination failed", profile: get, err: timeout, online: true,
			check: destinationCheck{delay: 212, status: 204, asked: true, elapsed: 3 * time.Second, err: timeout},
			want:  "Ping-config failed, proxy: NL, destination: GET " + dest + " failed after 3000 ms: context deadline exceeded, url " + url + " answered in 212 ms, network is up, alive: false",
		},
		{
			name: "url failed", profile: get, err: errors.New("dial tcp: i/o timeout"), online: true,
			want: "Ping-config failed, proxy: NL, destination: not asked, url " + url + " failed: dial tcp: i/o timeout, network is up, alive: false",
		},
		{
			name: "url status", profile: get, check: destinationCheck{status: 503},
			want: "Ping-config failed, proxy: NL, destination: not asked, url " + url + " failed: answered 503, alive: false",
		},
		{
			name: "the url only", profile: head, passed: true, alive: true,
			check: destinationCheck{delay: 212, status: 204},
			want:  "Ping-config passed, proxy: NL, destination: the url itself, delay: 212 ms from url " + url + ", alive: true",
		},
		{
			name: "kept by the window", profile: get, err: timeout, alive: true,
			check: destinationCheck{delay: 212, status: 204, asked: true, elapsed: 3 * time.Second, err: timeout},
			want:  "Ping-config failed, proxy: NL, destination: GET " + dest + " failed after 3000 ms: context deadline exceeded, url " + url + " answered in 212 ms, alive: true by the sampling window",
		},
	} {
		got := tc.check.line("NL", url, tc.profile, tc.err, tc.passed, tc.online, tc.alive)
		if got != tc.want {
			t.Errorf("%s:\n got %q\nwant %q", tc.name, got, tc.want)
		}
	}
}
