package handlers

import (
	"context"
	"errors"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestSoftwareReadCacheCoalescesWaitersAndFreshRefresh(t *testing.T) {
	var calls atomic.Int32
	started, release := make(chan struct{}), make(chan struct{})
	cache := newSoftwareProbeCache(func(ctx context.Context, _ string, _ ...string) ([]byte, error) {
		if calls.Add(1) == 1 {
			close(started)
			select {
			case <-release:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		return []byte("1.9.3"), nil
	})
	var wg sync.WaitGroup
	for range 24 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if result, err := cache.read(context.Background(), false, "ols", "-v"); err != nil || result != "1.9.3" {
				t.Errorf("read=%q, %v", result, err)
			}
		}()
	}
	<-started
	close(release)
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatalf("duplicate command executions=%d", calls.Load())
	}
	if _, err := cache.read(context.Background(), true, "ols", "-v"); err != nil || calls.Load() != 2 {
		t.Fatalf("fresh request did not refresh: calls=%d err=%v", calls.Load(), err)
	}
}

func TestSoftwareReadInvalidationRejectsStaleInFlightResult(t *testing.T) {
	var calls atomic.Int32
	started, release, oldDone := make(chan struct{}), make(chan struct{}), make(chan struct{})
	cache := newSoftwareProbeCache(func(context.Context, string, ...string) ([]byte, error) {
		if calls.Add(1) == 1 {
			close(started)
			<-release
			return []byte("old"), nil
		}
		return []byte("new"), nil
	})
	go func() {
		_, _ = cache.read(context.Background(), false, "version")
		close(oldDone)
	}()
	<-started
	cache.invalidate()
	if result, err := cache.read(context.Background(), false, "version"); err != nil || result != "new" {
		t.Fatalf("invalidated read joined old work: %q %v", result, err)
	}
	close(release)
	<-oldDone
	if result, err := cache.read(context.Background(), false, "version"); err != nil || result != "new" || calls.Load() != 2 {
		t.Fatalf("stale worker overwrote new cache: %q %v calls=%d", result, err, calls.Load())
	}
}

func TestSoftwareReadCacheExpiresAndDiscardsFailedOutput(t *testing.T) {
	var calls atomic.Int32
	cache := newSoftwareProbeCache(func(context.Context, string, ...string) ([]byte, error) {
		if calls.Add(1) == 1 {
			return []byte("misleading version before failure"), errors.New("read failed")
		}
		return []byte("recovered"), nil
	})
	if result, err := cache.read(context.Background(), false, "version"); err == nil || result != "" {
		t.Fatalf("failure produced an installed version: %q %v", result, err)
	}
	// Expire the actual entry deterministically without sleeping for its TTL.
	cache.mu.Lock()
	for key, result := range cache.entries {
		result.expires = time.Now().Add(-time.Second)
		cache.entries[key] = result
	}
	cache.mu.Unlock()
	if result, err := cache.read(context.Background(), false, "version"); err != nil || result != "recovered" || calls.Load() != 2 {
		t.Fatalf("expired failure prevented recovery: %q %v calls=%d", result, err, calls.Load())
	}
}

func TestSoftwareReadWorkersAreBoundedAndCallerCanCancel(t *testing.T) {
	var active, peak atomic.Int32
	release := make(chan struct{})
	started := make(chan struct{}, 12)
	cache := newSoftwareProbeCache(func(ctx context.Context, _ string, _ ...string) ([]byte, error) {
		current := active.Add(1)
		defer active.Add(-1)
		for previous := peak.Load(); current > previous && !peak.CompareAndSwap(previous, current); previous = peak.Load() {
		}
		started <- struct{}{}
		select {
		case <-release:
			return []byte("ok"), nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	})
	var wg sync.WaitGroup
	for index := range 12 {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			_, _ = cache.read(context.Background(), false, string(rune('a'+index)))
		}(index)
	}
	for range 4 {
		<-started
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := cache.read(ctx, false, "a"); !errors.Is(err, context.Canceled) {
		t.Fatalf("caller cancellation ignored: %v", err)
	}
	close(release)
	wg.Wait()
	if peak.Load() > 4 {
		t.Fatalf("unbounded process concurrency: %d", peak.Load())
	}
}

func TestSoftwareReadProcessHelper(t *testing.T) {
	if os.Getenv("OLS_SOFTWARE_READ_HELPER") != "1" {
		return
	}
	_, _ = os.Stdout.WriteString("partial version")
	time.Sleep(30 * time.Second)
	os.Exit(0)
}

func TestSoftwareReadCommandCancelsActualChildProcess(t *testing.T) {
	t.Setenv("OLS_SOFTWARE_READ_HELPER", "1")
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	started := time.Now()
	output, err := boundedSoftwareRead(ctx, os.Args[0], "-test.run=^TestSoftwareReadProcessHelper$")
	if !errors.Is(err, context.DeadlineExceeded) || len(output) != 0 {
		t.Fatalf("partial deadline output accepted: %q %v", output, err)
	}
	if time.Since(started) > 2*time.Second {
		t.Fatal("subprocess cancellation exceeded its budget")
	}
}

func TestSoftwareReadOutputLimitRejectsPartialEvidence(t *testing.T) {
	var output softwareProbeOutput
	chunk := make([]byte, softwareProbeOutputLimit+1)
	if n, err := output.Write(chunk); err != nil || n != len(chunk) {
		t.Fatalf("must drain producer output: %d %v", n, err)
	}
	if !output.exceeded || output.Len() != softwareProbeOutputLimit {
		t.Fatalf("unbounded capture: exceeded=%v size=%d", output.exceeded, output.Len())
	}
	if n, err := output.Write(chunk); err != nil || n != len(chunk) || output.Len() != softwareProbeOutputLimit {
		t.Fatal("overflow capture grew or stopped draining")
	}
}
