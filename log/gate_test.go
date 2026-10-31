//go:build with_powersave

package log

import "testing"

func TestGate(t *testing.T) {
	defer SetLevel(Level())
	defer SetGated(false)

	SetLevel(WARNING)

	SetGated(false)
	if !enabled(DEBUG) {
		t.Fatal("ungated: every event is produced")
	}

	SetGated(true)
	if enabled(DEBUG) || enabled(INFO) {
		t.Fatal("gated: below the level nothing is produced")
	}
	if !enabled(WARNING) || !enabled(ERROR) {
		t.Fatal("gated: from the level up everything is produced")
	}

	release := Want(INFO)
	if !enabled(INFO) || enabled(DEBUG) {
		t.Fatal("wanted info: info is produced, debug is not")
	}
	release()
	release()
	if enabled(INFO) {
		t.Fatal("released: info is not produced, and a second release changes nothing")
	}
}
