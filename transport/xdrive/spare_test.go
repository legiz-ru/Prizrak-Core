package xdrive

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
)

// gatedSlots is a slot storage whose slots are made only once gate opens or
// the context of the ring ends.
type gatedSlots struct {
	*memSlots
	started chan struct{}
	gate    chan struct{}
	once    sync.Once
	deleted atomic.Int32
}

func (g *gatedSlots) makeSlot(ctx context.Context, name string) (string, error) {
	g.once.Do(func() { close(g.started) })
	select {
	case <-g.gate:
	case <-ctx.Done():
		return "", ctx.Err()
	}
	return g.memSlots.makeSlot(ctx, name)
}

func (g *gatedSlots) Put(ctx context.Context, name string, data []byte) error { return nil }
func (g *gatedSlots) Get(ctx context.Context, name string) ([]byte, error) {
	return nil, errNotFound
}

func (g *gatedSlots) Delete(ctx context.Context, name string) error {
	if strings.HasPrefix(name, streamsDir+"/") {
		g.deleted.Add(1)
	}
	return nil
}
func (g *gatedSlots) List(ctx context.Context, prefix string) ([]Entry, error) { return nil, nil }
func (g *gatedSlots) Close() error                                             { return nil }

// A spare ring that was being made when the client closed used to land in
// the emptied box after Close, and nothing deleted it from the storage.
func TestCloseDropsTheSpareBeingMade(t *testing.T) {
	store := &gatedSlots{memSlots: newMemSlots(), started: make(chan struct{}), gate: make(chan struct{})}
	client := NewClient(&Config{}, nil)
	client.build = func() (Storage, error) { return store, nil }

	client.warmSpares(paramsFromConfig(&Config{}))
	select {
	case <-store.started:
	case <-time.After(10 * time.Second):
		t.Fatal("no spare ring was started")
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	close(store.gate)

	deadline := time.Now().Add(5 * time.Second)
	for client.box.busy.Load() {
		if time.Now().After(deadline) {
			t.Fatal("the filler did not stop after Close")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if n := len(client.box.ch); n != 0 {
		t.Fatalf("%d spare rings left after Close", n)
	}
	if store.deleted.Load() == 0 {
		t.Fatal("the spare ring that was being made was not deleted")
	}
}

// A health check opens a session but does not keep the spare rings warm: with
// one every few minutes the rings of an unused client were made and deleted
// again for as long as the client lived.
func TestHealthCheckDoesNotWarmSpares(t *testing.T) {
	store := &gatedSlots{memSlots: newMemSlots(), started: make(chan struct{}), gate: make(chan struct{})}
	close(store.gate)
	client := NewClient(&Config{}, nil)
	client.build = func() (Storage, error) { return store, nil }
	defer client.Close()

	conn, err := client.Dial(C.WithHealthCheck(context.Background()))
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if client.box.last.Load() != 0 || client.box.busy.Load() {
		t.Fatal("a health check warmed the spare rings")
	}

	conn, err = client.Dial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if client.box.last.Load() == 0 {
		t.Fatal("a dial for traffic did not warm the spare rings")
	}
}
