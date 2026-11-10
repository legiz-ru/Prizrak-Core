package xdrive

import (
	"sync"

	"golang.org/x/exp/constraints"
)

// The module is built as go 1.20, without the min and max builtins.

func min[T constraints.Ordered](a, b T) T {
	if a < b {
		return a
	}
	return b
}

func max[T constraints.Ordered](a, b T) T {
	if a > b {
		return a
	}
	return b
}

// onceFunc is sync.OnceFunc of Go 1.21.
func onceFunc(f func()) func() {
	var once sync.Once
	return func() { once.Do(f) }
}
