package tls

import (
	"fmt"
	"io"
	"os"
)

func OpenMasterKeyLog(path string) (io.Writer, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open master key log: %w", err)
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("secure master key log permissions: %w", err)
	}
	return file, nil
}
