// Ported from Xray-core v26.11.9 transport/internet/xdrive
// (https://github.com/XTLS/Xray-core), which is licensed under the Mozilla
// Public License 2.0; this file stays under MPL-2.0.
// SPDX-License-Identifier: MPL-2.0

package xdrive

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path"
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
	return clean[1:], nil
}

func (s *localStorage) openParent(root *os.Root, name string) (*os.Root, string, error) {
	parts := strings.Split(name, "/")
	leaf := parts[len(parts)-1]
	parent := root
	var owned *os.Root
	for _, part := range parts[:len(parts)-1] {
		next, err := parent.OpenRoot(part)
		if err != nil {
			if owned != nil {
				_ = owned.Close()
			}
			return nil, "", err
		}
		if owned != nil {
			_ = owned.Close()
		}
		owned = next
		parent = next
	}
	if owned == nil {
		var err error
		owned, err = root.OpenRoot(".")
		if err != nil {
			return nil, "", err
		}
	}
	return owned, leaf, nil
}

func (s *localStorage) Put(ctx context.Context, name string, data []byte) error {
	root, err := os.OpenRoot(s.root)
	if err != nil {
		return newError("failed to open remote folder").Base(err)
	}
	defer root.Close()
	full, err := s.resolve(name)
	if err != nil {
		return err
	}
	dir := path.Dir(full)
	if dir != "." {
		if err := root.MkdirAll(dir, 0o700); err != nil {
			return newError("failed to create folder ", dir).Base(err)
		}
	}

	var tmp *os.File
	var tmpName string
	for attempt := 0; attempt < 10; attempt++ {
		suffix := make([]byte, 12)
		if _, err := rand.Read(suffix); err != nil {
			return newError("failed to create temp file name in ", dir).Base(err)
		}
		tmpName = path.Join(dir, tempPrefix+hex.EncodeToString(suffix))
		tmp, err = root.OpenFile(tmpName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if !os.IsExist(err) {
			break
		}
	}
	if err != nil {
		return newError("failed to create temp file in ", dir).Base(err)
	}
	defer root.Remove(tmpName)

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return newError("failed to write ", name).Base(err)
	}
	if err := tmp.Close(); err != nil {
		return newError("failed to close ", name).Base(err)
	}
	if err := root.Rename(tmpName, full); err != nil {
		return newError("failed to commit ", name).Base(err)
	}
	return nil
}

func (s *localStorage) Get(ctx context.Context, name string) ([]byte, error) {
	root, err := os.OpenRoot(s.root)
	if err != nil {
		return nil, newError("failed to open remote folder").Base(err)
	}
	defer root.Close()
	full, err := s.resolve(name)
	if err != nil {
		return nil, err
	}
	data, err := readFile(ctx, root, full)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, errNotFound
		}
		return nil, newError("failed to read ", name).Base(err)
	}
	return data, nil
}

func (s *localStorage) Delete(ctx context.Context, name string) error {
	root, err := os.OpenRoot(s.root)
	if err != nil {
		return newError("failed to open remote folder").Base(err)
	}
	defer root.Close()
	full, err := s.resolve(name)
	if err != nil {
		return err
	}
	parent, leaf, err := s.openParent(root, full)
	if err != nil {
		return newError("failed to resolve parent folder for ", name).Base(err)
	}
	defer parent.Close()
	if err := parent.RemoveAll(leaf); err != nil {
		return newError("failed to delete ", name).Base(err)
	}
	return nil
}

func (s *localStorage) List(ctx context.Context, prefix string) ([]Entry, error) {
	root, err := os.OpenRoot(s.root)
	if err != nil {
		return nil, newError("failed to open remote folder").Base(err)
	}
	defer root.Close()
	full, err := s.resolve(prefix)
	if err != nil {
		return nil, err
	}
	dir, err := root.Open(full)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, newError("failed to list ", prefix).Base(err)
	}
	defer dir.Close()
	entries, err := dir.ReadDir(-1)
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
