package goatcounter_test

import (
	"sync"
	"testing"

	. "zgo.at/goatcounter/v2"
	"zgo.at/goatcounter/v2/gctest"
	"zgo.at/zstd/zint"
)

func TestSessionIDConcurrent(t *testing.T) {
	gctest.DB(t)

	const N = 1000
	results := make([]zint.Uint128, N)
	var wg sync.WaitGroup
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			results[idx] = Memstore.SessionID()
		}(i)
	}
	wg.Wait()

	seen := make(map[zint.Uint128]struct{}, N)
	for _, r := range results {
		if _, ok := seen[r]; ok {
			t.Errorf("duplicate session ID: %v", r)
		}
		seen[r] = struct{}{}
	}
	if len(seen) != N {
		t.Errorf("got %d unique IDs, want %d", len(seen), N)
	}
}
