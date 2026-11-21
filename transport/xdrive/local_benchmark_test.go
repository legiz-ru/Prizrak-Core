package xdrive

import (
	"context"
	"fmt"
	"testing"
)

func BenchmarkLocalStoragePutGetDelete(b *testing.B) {
	storage, err := newLocalStorage(b.TempDir())
	if err != nil {
		b.Fatal(err)
	}
	defer storage.Close()

	data := make([]byte, 1024)
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		name := fmt.Sprintf("object-%d", i)
		if err := storage.Put(context.Background(), name, data); err != nil {
			b.Fatal(err)
		}
		if _, err := storage.Get(context.Background(), name); err != nil {
			b.Fatal(err)
		}
		if err := storage.Delete(context.Background(), name); err != nil {
			b.Fatal(err)
		}
	}
}
