// Package fragment splits the start of a TCP stream to get past DPI that
// matches the TLS ClientHello in one piece.
//
// The modes and the length/interval/max-split semantics follow the freedom
// outbound of Xray-core (proxy/freedom, FragmentWriter). Splitting at the
// server name labels and waiting for the peer's ACK between segments follow
// sing-box (common/tlsfragment).
package fragment

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

const DefaultFallbackDelay = 500 * time.Millisecond

type Config struct {
	// PacketsFrom/PacketsTo as in Xray: 0/1 splits the first TLS ClientHello
	// into TLS records ("tlshello"), 0/0 splits every write into TCP segments
	// (""), N/M splits writes N to M into TCP segments ("N-M").
	PacketsFrom, PacketsTo uint64
	LengthMin, LengthMax   uint64
	IntervalMin            uint64 // milliseconds
	IntervalMax            uint64
	MaxSplitMin            uint64
	MaxSplitMax            uint64

	// SplitSNI cuts inside the labels of the server name instead of into
	// pieces of LengthMin..LengthMax bytes; writes without a server name pass
	// unchanged.
	SplitSNI bool
	// WaitAck sends every piece in its own TCP segment and waits until the
	// peer acknowledged it, instead of pausing for the interval.
	WaitAck       bool
	FallbackDelay time.Duration
}

type Option struct {
	Packets       string
	Length        string
	Interval      string
	MaxSplit      string
	Split         string // "length" (default) or "sni"
	Wait          string // "interval" (default) or "ack"
	FallbackDelay int    // milliseconds
}

func (c *Config) TLSHello() bool { return c.PacketsFrom == 0 && c.PacketsTo == 1 }

// separate reports whether the pieces go out one by one instead of in one write.
func (c *Config) separate() bool { return c.WaitAck || c.IntervalMax > 0 }

func NewConfig(o Option) (*Config, error) {
	c := &Config{FallbackDelay: DefaultFallbackDelay}
	switch strings.ToLower(strings.TrimSpace(o.Packets)) {
	case "tlshello":
		c.PacketsFrom, c.PacketsTo = 0, 1
	case "":
	default:
		from, to, err := parseRange(o.Packets)
		if err != nil {
			return nil, fmt.Errorf("fragment packets: %w", err)
		}
		if from == 0 {
			return nil, fmt.Errorf("fragment packets: the first packet is 1, not 0")
		}
		c.PacketsFrom, c.PacketsTo = from, to
	}

	switch strings.ToLower(strings.TrimSpace(o.Split)) {
	case "", "length":
	case "sni":
		c.SplitSNI = true
	default:
		return nil, fmt.Errorf("fragment split: unknown mode %q, want length or sni", o.Split)
	}
	switch strings.ToLower(strings.TrimSpace(o.Wait)) {
	case "", "interval":
	case "ack":
		c.WaitAck = true
	default:
		return nil, fmt.Errorf("fragment wait: unknown mode %q, want interval or ack", o.Wait)
	}

	if !c.SplitSNI {
		if strings.TrimSpace(o.Length) == "" {
			return nil, fmt.Errorf("fragment length is required with split: length")
		}
		var err error
		if c.LengthMin, c.LengthMax, err = parseRange(o.Length); err != nil {
			return nil, fmt.Errorf("fragment length: %w", err)
		}
		if c.LengthMin == 0 {
			return nil, fmt.Errorf("fragment length can't be 0")
		}
		if o.MaxSplit != "" {
			if c.MaxSplitMin, c.MaxSplitMax, err = parseRange(o.MaxSplit); err != nil {
				return nil, fmt.Errorf("fragment max-split: %w", err)
			}
		}
	}
	if o.Interval != "" {
		var err error
		if c.IntervalMin, c.IntervalMax, err = parseRange(o.Interval); err != nil {
			return nil, fmt.Errorf("fragment interval: %w", err)
		}
	}
	if o.FallbackDelay < 0 {
		return nil, fmt.Errorf("fragment fallback-delay can't be negative")
	}
	if o.FallbackDelay > 0 {
		c.FallbackDelay = time.Duration(o.FallbackDelay) * time.Millisecond
	}
	return c, nil
}

// parseRange reads "N" or "N-M" as in Xray; a reversed range is swapped.
func parseRange(s string) (uint64, uint64, error) {
	s = strings.TrimSpace(s)
	a, b, isRange := strings.Cut(s, "-")
	from, err := strconv.ParseUint(strings.TrimSpace(a), 10, 32)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid range %q", s)
	}
	to := from
	if isRange {
		if to, err = strconv.ParseUint(strings.TrimSpace(b), 10, 32); err != nil {
			return 0, 0, fmt.Errorf("invalid range %q", s)
		}
	}
	if from > to {
		from, to = to, from
	}
	return from, to, nil
}
