// Ported from Xray-core v26.11.9 transport/internet/xdrive
// (https://github.com/XTLS/Xray-core), which is licensed under the Mozilla
// Public License 2.0; this file stays under MPL-2.0.
// SPDX-License-Identifier: MPL-2.0

package xdrive

import (
	"context"
	"errors"
	"os"
	"time"

	"golang.org/x/sys/windows"
)

// readFile retries os.ReadFile for up to 2 seconds on sharing violations:
// os.Rename (MoveFileEx) in Put holds the file with DELETE access, which
// os.ReadFile does not share, until a moment after its new name appears in List
func readFile(ctx context.Context, name string) ([]byte, error) {
	deadline := time.Now().Add(2 * time.Second)
	delay := time.Millisecond
	for {
		data, err := os.ReadFile(name)
		if !errors.Is(err, windows.ERROR_SHARING_VIOLATION) || time.Now().Add(delay).After(deadline) {
			return data, err
		}
		select {
		case <-ctx.Done():
			return nil, err
		case <-time.After(delay):
		}
		delay = min(2*delay, 100*time.Millisecond)
	}
}
