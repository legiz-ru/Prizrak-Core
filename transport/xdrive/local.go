// Ported from Xray-core v26.11.9 transport/internet/xdrive
// (https://github.com/XTLS/Xray-core), which is licensed under the Mozilla
// Public License 2.0; this file stays under MPL-2.0.
// SPDX-License-Identifier: MPL-2.0

package xdrive

import (
	"context"
	"os"
	"path"
	"path/filepath"
	"strings"
)

const tempPrefix = ".xdrive-tmp-"

type localStorage struct {
	root string
}

func newLocalStorage(root string) (*localStorage, error) {
	if root == "" {
		return nil, newError(`empty "remoteFolder"`)
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, newError("failed to create remote folder").Base(err)
	}
	return &localStorage{root: root}, nil
}

func (s *localStorage) resolve(name string) (string, error) {
	clean := path.Clean("/" + name)
	if clean == "/" {
		return "", newError("invalid object name: ", name)
	}
	if strings.HasPrefix(path.Base(clean), tempPrefix) {
		return "", newError("reserved object name: ", name)
	}
	return filepath.Join(s.root, filepath.FromSlash(clean[1:])), nil
}

func (s *localStorage) Put(ctx context.Context, name string, data []byte) error {
	full, err := s.resolve(name)
	if err != nil {
		return err
	}
	dir := filepath.Dir(full)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return newError("failed to create folder ", dir).Base(err)
	}

	tmp, err := os.CreateTemp(dir, tempPrefix+"*")
	if err != nil {
		return newError("failed to create temp file in ", dir).Base(err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return newError("failed to write ", name).Base(err)
	}
	if err := tmp.Close(); err != nil {
		return newError("failed to close ", name).Base(err)
	}
	if err := os.Rename(tmpName, full); err != nil {
		return newError("failed to commit ", name).Base(err)
	}
	return nil
}

func (s *localStorage) Get(ctx context.Context, name string) ([]byte, error) {
	full, err := s.resolve(name)
	if err != nil {
		return nil, err
	}
	data, err := readFile(ctx, full)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, errNotFound
		}
		return nil, newError("failed to read ", name).Base(err)
	}
	return data, nil
}

func (s *localStorage) Delete(ctx context.Context, name string) error {
	full, err := s.resolve(name)
	if err != nil {
		return err
	}
	if err := os.RemoveAll(full); err != nil {
		return newError("failed to delete ", name).Base(err)
	}
	return nil
}

func (s *localStorage) List(ctx context.Context, prefix string) ([]Entry, error) {
	full, err := s.resolve(prefix)
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(full)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, newError("failed to list ", prefix).Base(err)
	}
	found := make([]Entry, 0, len(entries))
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), tempPrefix) {
			continue
		}
		found = append(found, Entry{Name: entry.Name()})
	}
	return found, nil
}

func (s *localStorage) Close() error {
	return nil
}
