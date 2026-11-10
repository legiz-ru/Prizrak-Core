//go:build !windows

// Ported from Xray-core v26.11.9 transport/internet/xdrive
// (https://github.com/XTLS/Xray-core), which is licensed under the Mozilla
// Public License 2.0; this file stays under MPL-2.0.
// SPDX-License-Identifier: MPL-2.0

package xdrive

import (
	"context"
	"os"
)

func readFile(_ context.Context, name string) ([]byte, error) {
	return os.ReadFile(name)
}
