package pingconfig

import (
	"math/rand"
	"sort"
	"time"

	C "github.com/metacubex/mihomo/constant"
)

// Slot is one check of a cycle: node Node at Offset from the cycle start.
type Slot struct {
	Node   int
	Offset time.Duration
}

// Plan lays out a cycle of nodes checks: each node Sampling times, the
// k-th at a random moment of the k-th interval, so a node's checks are
// spread over the cycle and different nodes are not checked at once.
// The slots come in time order.
func Plan(nodes int, p *Profile, rnd *rand.Rand) []Slot {
	slots := make([]Slot, 0, nodes*p.Sampling)
	for k := 0; k < p.Sampling; k++ {
		base := time.Duration(k) * p.Interval
		for i := 0; i < nodes; i++ {
			slots = append(slots, Slot{Node: i, Offset: base + time.Duration(rnd.Int63n(int64(p.Interval)))})
		}
	}
	sort.SliceStable(slots, func(a, b int) bool { return slots[a].Offset < slots[b].Offset })
	return slots
}

// WindowStats judges a node by the results within window before now, as
// Xray does with sampling: alive if any of them succeeded, its delay the
// mean of those that did. With no result in the window the last one
// decides, so a pause in checks (lazy, power save) does not kill a node.
func WindowStats(history []C.DelayHistory, now time.Time, window time.Duration) (alive bool, delay uint16) {
	if len(history) == 0 {
		return false, 0
	}
	var sum, n int
	inWindow := false
	for _, h := range history {
		if now.Sub(h.Time) > window {
			continue
		}
		inWindow = true
		if h.Delay > 0 {
			sum += int(h.Delay)
			n++
		}
	}
	if !inWindow {
		last := history[len(history)-1]
		return last.Delay > 0, last.Delay
	}
	if n == 0 {
		return false, 0
	}
	return true, uint16(sum / n)
}
