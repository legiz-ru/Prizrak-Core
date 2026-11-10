// Ported from Xray-core v26.11.9 transport/internet/xdrive
// (https://github.com/XTLS/Xray-core), which is licensed under the Mozilla
// Public License 2.0; this file stays under MPL-2.0.
// SPDX-License-Identifier: MPL-2.0

package xdrive

import (
	"context"
	"sync/atomic"
)

var errNotFound = newError("object not found")

type Entry struct {
	Name   string
	Inline []byte
}

type Storage interface {
	Put(ctx context.Context, name string, data []byte) error
	Get(ctx context.Context, name string) ([]byte, error)
	Delete(ctx context.Context, name string) error
	List(ctx context.Context, prefix string) ([]Entry, error)
	Close() error
}

// testStorageFactory lets tests substitute a backend for newStorage; nil in
// production so behaviour is unchanged.
var testStorageFactory atomic.Pointer[func(config *Config) (Storage, error)]

func newStorage(config *Config, dialer *Dialer) (Storage, error) {
	if f := testStorageFactory.Load(); f != nil {
		return (*f)(config)
	}

	switch config.Service {
	case "local":
		return newLocalStorage(config.RemoteFolder)
	case "google-drive", "Google Drive":
		return newDriveStorage(dialer, config)
	case "template":
		return newTemplateStorage(dialer, config)
	case "s3":
		return newS3Storage(dialer, config)
	default:
		return nil, newError("unsupported service: ", config.Service)
	}
}

// sessionStorage returns the storage of one session, which takes connections
// of XMUX until Close, with the token and cache of storage. Local storage has
// no connections
func sessionStorage(storage Storage) Storage {
	switch s := storage.(type) {
	case *driveStorage:
		return s.session()
	case *templateStorage:
		return s.session()
	case *s3Storage:
		return s.session()
	}
	return storage
}
