package finalmask

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"strconv"
	"strings"
)

// RandBetween returns a value in [from, to), or from when the range holds at
// most one value, as Xray's crypto.RandBetween.
func RandBetween(from, to int64) int64 {
	if from > to {
		from, to = to, from
	}
	if d := to - from; d == 0 || d == 1 {
		return from
	}
	n, _ := rand.Int(rand.Reader, big.NewInt(to-from))
	return from + n.Int64()
}

// RandBytesBetween fills b with random bytes in [from, to].
func RandBytesBetween(b []byte, from, to byte) {
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	if from > to {
		from, to = to, from
	}
	if to-from == 255 {
		return
	}
	for i := range b {
		b[i] = from + b[i]%(to-from+1)
	}
}

// Range is a value or an "a-b" range as Xray writes them in its JSON config:
// "10" and 10 are [10, 10], "10-20" is [10, 20]. The bounds are kept in the
// order given; a mask that draws from the range swaps them if needed.
type Range struct {
	From, To int
}

func (r Range) String() string {
	if r.From == r.To {
		return strconv.Itoa(r.From)
	}
	return fmt.Sprintf("%d-%d", r.From, r.To)
}

// IsZero reports whether the range was left out of the config.
func (r Range) IsZero() bool { return r.From == 0 && r.To == 0 }

func (r *Range) UnmarshalText(text []byte) error {
	from, to, err := ParseRange(string(text))
	if err != nil {
		return err
	}
	r.From, r.To = from, to
	return nil
}

// ParseRange reads "N" or "N-M" (negative numbers included, as "-1" or
// "-5--1"); "" is 0.
func ParseRange(s string) (int, int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, 0, nil
	}
	if v, err := strconv.Atoi(s); err == nil {
		return v, v, nil
	}
	// A leading minus belongs to the first number: "-5--1".
	cut := strings.Index(s[1:], "-")
	if cut >= 0 {
		left, err1 := strconv.Atoi(s[:cut+1])
		right, err2 := strconv.Atoi(s[cut+2:])
		if err1 == nil && err2 == nil {
			return left, right, nil
		}
	}
	return 0, 0, fmt.Errorf("invalid range %q", s)
}
