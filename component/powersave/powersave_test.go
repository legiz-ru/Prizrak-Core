//go:build with_powersave

package powersave

import "testing"

func TestChanged(t *testing.T) {
	defer Set(Active)

	ch := Changed()
	Set(Active)
	select {
	case <-ch:
		t.Fatal("the same mode again is no change")
	default:
	}

	Set(Idle)
	select {
	case <-ch:
	default:
		t.Fatal("a new mode closes the channel")
	}
	if Current() != Idle {
		t.Fatal("Current follows Set")
	}
}
