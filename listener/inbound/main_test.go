package inbound_test

import (
	"os"
	"testing"

	C "github.com/metacubex/mihomo/constant"
)

// TestMain points the home directory at a temporary one: the folder of an
// xdrive listener or proxy with service local has to be in it or in
// SAFE_PATHS.
func TestMain(m *testing.M) {
	home, err := os.MkdirTemp("", "mihomo-inbound-test-")
	if err != nil {
		panic(err)
	}
	C.SetHomeDir(home)
	code := m.Run()
	_ = os.RemoveAll(home)
	os.Exit(code)
}

// homeTempDir is t.TempDir under the home directory.
func homeTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp(C.Path.HomeDir(), "test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}
