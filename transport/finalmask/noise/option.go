package noise

import (
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/metacubex/mihomo/transport/finalmask"
	"github.com/metacubex/mihomo/transport/finalmask/custom"
)

// Option is the mask's settings as written in the config.
type Option struct {
	// Reset, in seconds, is how long the noise is not repeated to a peer;
	// 0 sends it once.
	Reset finalmask.Range `proxy:"reset,omitempty"`
	Noise []ItemOption    `proxy:"noise,omitempty"`
}

// ItemOption is one noise packet. Rand sends that many random bytes in
// RandRange; Packet sends fixed bytes (Type: str, hex, base64, or a list of
// byte values); Type "exp" composes the packet from Packet's expression:
// "<b 0d0a> <t> <c> <n> <r 24> <rc 8-16> <rd 4>" are fixed hex bytes, a
// 4-byte timestamp, a 4-byte counter, an 8-byte nonce, random bytes, random
// letters and random digits of the given size.
type ItemOption struct {
	Rand      finalmask.Range  `proxy:"rand,omitempty"`
	RandRange *finalmask.Range `proxy:"rand-range,omitempty"`
	Type      string           `proxy:"type,omitempty"`
	Packet    any              `proxy:"packet,omitempty"`
	Delay     finalmask.Range  `proxy:"delay,omitempty"`
}

func New(o Option) (*Config, error) {
	items := make([]*Item, 0, len(o.Noise))
	for i, item := range o.Noise {
		built, err := item.build()
		if err != nil {
			return nil, fmt.Errorf("noise item %d: %w", i, err)
		}
		items = append(items, built)
	}
	resetMin, resetMax := int64(o.Reset.From), int64(o.Reset.To)
	if resetMin > resetMax {
		resetMin, resetMax = resetMax, resetMin
	}
	if resetMin < 0 {
		return nil, errors.New("noise reset can't be negative")
	}
	return &Config{ResetMin: resetMin, ResetMax: resetMax, Items: items}, nil
}

func (it ItemOption) build() (*Item, error) {
	randMin, randMax := int64(it.Rand.From), int64(it.Rand.To)
	if randMin > randMax {
		randMin, randMax = randMax, randMin
	}
	if randMin < 0 {
		return nil, errors.New("rand can't be negative")
	}
	delayMin, delayMax := int64(it.Delay.From), int64(it.Delay.To)
	if delayMin > delayMax {
		delayMin, delayMax = delayMax, delayMin
	}
	if delayMin < 0 {
		return nil, errors.New("delay can't be negative")
	}
	if it.Packet != nil && randMax > 0 {
		return nil, errors.New("packet and rand are exclusive")
	}
	if strings.EqualFold(it.Type, "exp") {
		exp, ok := it.Packet.(string)
		if !ok {
			return nil, errors.New(`packet of type "exp" must be a string`)
		}
		segments, err := ParseExp(exp)
		if err != nil {
			return nil, err
		}
		return &Item{Segments: segments, DelayMin: delayMin, DelayMax: delayMax}, nil
	}
	rangeMin, rangeMax := 0, 255
	if it.RandRange != nil {
		rangeMin, rangeMax = it.RandRange.From, it.RandRange.To
		if rangeMin > rangeMax {
			rangeMin, rangeMax = rangeMax, rangeMin
		}
		if rangeMin < 0 || rangeMax > 255 {
			return nil, fmt.Errorf("invalid rand-range %s", it.RandRange)
		}
	}
	packet, err := custom.ParseBytes(it.Packet, it.Type)
	if err != nil {
		return nil, err
	}
	if randMax == 0 && len(packet) == 0 {
		return nil, errors.New("either packet or rand is required")
	}
	return &Item{
		RandMin:      randMin,
		RandMax:      randMax,
		RandRangeMin: int32(rangeMin),
		RandRangeMax: int32(rangeMax),
		Packet:       packet,
		DelayMin:     delayMin,
		DelayMax:     delayMax,
	}, nil
}

var expPattern = regexp.MustCompile(`<\s*([a-z]+)(?:\s+([^>]*?))?\s*>`)

// ParseExp reads a composed packet expression, see ItemOption.
func ParseExp(exp string) ([]*Segment, error) {
	var segments []*Segment
	matches := expPattern.FindAllStringSubmatchIndex(exp, -1)
	last := 0
	for _, m := range matches {
		if strings.TrimSpace(exp[last:m[0]]) != "" {
			return nil, fmt.Errorf("invalid noise exp near %q", exp[last:m[0]])
		}
		last = m[1]
		key := exp[m[2]:m[3]]
		arg := ""
		if m[4] >= 0 {
			arg = exp[m[4]:m[5]]
		}
		segment, err := buildSegment(key, arg)
		if err != nil {
			return nil, err
		}
		segments = append(segments, segment)
	}
	if strings.TrimSpace(exp[last:]) != "" {
		return nil, fmt.Errorf("invalid noise exp near %q", exp[last:])
	}
	if len(segments) == 0 {
		return nil, fmt.Errorf("empty noise exp %q", exp)
	}
	return segments, nil
}

func buildSegment(key, arg string) (*Segment, error) {
	sizeSegment := func(kind SegmentKind) (*Segment, error) {
		if arg == "" {
			return nil, fmt.Errorf("<%s> in noise exp needs a size", key)
		}
		lo, hi, err := finalmask.ParseRange(arg)
		if err != nil {
			return nil, err
		}
		if lo < 0 || hi < lo || hi > 65535 {
			return nil, fmt.Errorf("invalid size in noise exp: %s", arg)
		}
		return &Segment{Kind: kind, MinSize: int64(lo), MaxSize: int64(hi)}, nil
	}
	noArg := func(kind SegmentKind) (*Segment, error) {
		if arg != "" {
			return nil, fmt.Errorf("<%s> in noise exp takes no argument", key)
		}
		return &Segment{Kind: kind}, nil
	}
	switch key {
	case "b":
		hexStr := strings.TrimPrefix(strings.TrimPrefix(strings.Join(strings.Fields(arg), ""), "0x"), "0X")
		if len(hexStr) == 0 {
			return nil, errors.New("empty bytes in noise exp")
		}
		raw, err := hex.DecodeString(hexStr)
		if err != nil {
			return nil, fmt.Errorf("invalid hex in noise exp %q: %w", arg, err)
		}
		return &Segment{Kind: SegmentBytes, Bytes: raw}, nil
	case "r":
		return sizeSegment(SegmentRandom)
	case "rc":
		return sizeSegment(SegmentRandomASCII)
	case "rd":
		return sizeSegment(SegmentRandomDigit)
	case "t":
		return noArg(SegmentTimestamp)
	case "c":
		return noArg(SegmentCounter)
	case "n":
		return noArg(SegmentNonce)
	default:
		return nil, fmt.Errorf("unknown <%s> in noise exp", key)
	}
}
