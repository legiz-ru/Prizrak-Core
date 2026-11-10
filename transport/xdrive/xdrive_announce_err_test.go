// Ported from Xray-core v26.11.9 transport/internet/xdrive tests
// (https://github.com/XTLS/Xray-core), which is licensed under the Mozilla
// Public License 2.0; this file stays under MPL-2.0.
// SPDX-License-Identifier: MPL-2.0

package xdrive

import (
	"context"
	"strings"
	"testing"
	"time"
)

// failPutStore is a slotStore whose Put always fails, to exercise the announce
// failure path without any network.
type failPutStore struct {
	*memSlots
}

func (s *failPutStore) Put(ctx context.Context, name string, data []byte) error {
	return newError("put refused")
}

func (s *failPutStore) Close() error { return nil }

func (s *failPutStore) Get(ctx context.Context, name string) ([]byte, error) {
	return nil, errNotFound
}

func (s *failPutStore) List(ctx context.Context, prefix string) ([]Entry, error) {
	return nil, nil
}

func (s *failPutStore) Delete(ctx context.Context, name string) error { return nil }

func TestDialAnnounceFailureFailsRead(t *testing.T) {
	store := &failPutStore{memSlots: newMemSlots()}
	factory := func(*Config) (Storage, error) { return store, nil }
	testStorageFactory.Store(&factory)
	t.Cleanup(func() { testStorageFactory.Store(nil) })

	client := NewClient(&Config{
		Service:           "sim",
		RemoteFolder:      "x",
		Secrets:           []string{"a", "b", "c"},
		Concurrency:       4,
		FlushIntervalMs:   1,
		PollIntervalMs:    1,
		MaxPollIntervalMs: 5,
		SessionTtlSeconds: 60,
	}, nil)
	defer client.Close()
	conn, err := client.Dial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	go conn.Write([]byte("hello"))

	type result struct {
		n   int
		err error
	}
	done := make(chan result, 1)
	go func() {
		n, err := conn.Read(make([]byte, 16))
		done <- result{n, err}
	}()
	select {
	case r := <-done:
		if r.err == nil || !strings.Contains(r.err.Error(), "failed to announce") {
			t.Fatalf("Read returned %v, want the announce error", r.err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Read blocked after the announcement failed")
	}

	// The reader loop must have exited: it no longer polls the store.
	store.mu.Lock()
	before := store.reads
	store.mu.Unlock()
	time.Sleep(100 * time.Millisecond)
	store.mu.Lock()
	after := store.reads
	store.mu.Unlock()
	if after != before {
		t.Fatalf("reader kept polling after the announce failure: %d -> %d", before, after)
	}
}
