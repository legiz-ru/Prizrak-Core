package xdrive

import (
	"math"
	"testing"
)

func s3Options() Options {
	return Options{
		Service:      "s3",
		RemoteFolder: "x",
		Secrets:      []string{"AKIDEXAMPLE", "secret"},
		S3:           &S3Options{Endpoint: "http://127.0.0.1:9", Region: "us-east-1", Bucket: "b"},
	}
}

// A reuse-settings range past int32 used to be cut to int32 and to make the
// XMUX manager panic on the first dial, which took the whole core down.
func TestReuseSettingsOutOfInt32Range(t *testing.T) {
	for _, value := range []string{"1-2147483649", "2147483648", "4294967296"} {
		options := s3Options()
		options.ReuseSettings = &ReuseSettings{MaxConcurrency: value}
		if _, err := options.Build(false); err == nil {
			t.Errorf("max-concurrency %q: Build accepted a range past int32", value)
		}
	}

	options := s3Options()
	options.ReuseSettings = &ReuseSettings{MaxConcurrency: "1-2147483647"}
	config, err := options.Build(false)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	newXmuxManager(*config.Xmux, func() xmuxConn { return nil })
}

func TestRandRangeWholeInt32(t *testing.T) {
	for _, r := range []Range{
		{From: math.MinInt32, To: math.MaxInt32},
		{From: math.MaxInt32, To: math.MinInt32},
		{From: -5, To: math.MaxInt32},
		{From: 1, To: math.MaxInt32},
	} {
		from, to := int64(r.From), int64(r.To)
		if from > to {
			from, to = to, from
		}
		for i := 0; i < 64; i++ {
			got := int64(randRange(&r))
			if got < from || got >= to {
				t.Fatalf("randRange(%+v) = %d, want [%d, %d)", r, got, from, to)
			}
		}
	}
	if got := randRange(&Range{From: 7, To: 8}); got != 7 {
		t.Fatalf("randRange(7-8) = %d, want 7", got)
	}
}

// Negative numbers used to wrap around to huge uint32 values: a concurrency
// of -1 made a channel of 4294967295 slots, which panics on 32-bit builds.
func TestOptionsRejectNegativeNumbers(t *testing.T) {
	for name, set := range map[string]func(*Options){
		"segment-bytes":        func(o *Options) { o.SegmentBytes = -1 },
		"flush-interval-ms":    func(o *Options) { o.FlushIntervalMs = -1 },
		"poll-interval-ms":     func(o *Options) { o.PollIntervalMs = -1 },
		"max-poll-interval-ms": func(o *Options) { o.MaxPollIntervalMs = -1 },
		"session-ttl-seconds":  func(o *Options) { o.SessionTtlSeconds = -1 },
		"concurrency":          func(o *Options) { o.Concurrency = -1 },
		"eager-window-ms":      func(o *Options) { o.EagerWindowMs = -1 },
		"hole-timeout-ms":      func(o *Options) { o.HoleTimeoutMs = -1 },
	} {
		options := s3Options()
		set(&options)
		if _, err := options.Build(false); err == nil {
			t.Errorf("%s: Build accepted -1", name)
		}
	}

	options := s3Options()
	options.Concurrency = 4
	if _, err := options.Build(false); err != nil {
		t.Fatalf("Build: %v", err)
	}
}

func TestCappedLargeValue(t *testing.T) {
	if got := capped(math.MaxUint32, 8, 256); got != 256 {
		t.Fatalf("capped(MaxUint32) = %d, want 256", got)
	}
	if got := capped(0, 8, 256); got != 8 {
		t.Fatalf("capped(0) = %d, want 8", got)
	}
}
