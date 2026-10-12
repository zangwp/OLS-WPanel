package handlers

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type observedCacheContext struct {
	context.Context
	entered chan struct{}
	once    sync.Once
}

func (ctx *observedCacheContext) Done() <-chan struct{} {
	ctx.once.Do(func() { close(ctx.entered) })
	return ctx.Context.Done()
}

func TestReadCacheMergesRefreshesAndCancelsOnlySubscriber(t *testing.T) {
	var cache readCache[int]
	var calls atomic.Int32
	entered, release := make(chan struct{}, 1), make(chan struct{})
	load := func(ctx context.Context) (int, error) {
		calls.Add(1)
		entered <- struct{}{}
		select {
		case <-release:
			return 42, nil
		case <-ctx.Done():
			return 0, ctx.Err()
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	first := make(chan error, 1)
	go func() { _, err := cache.get(ctx, "key", false, time.Minute, time.Second, load); first <- err }()
	<-entered
	second := make(chan int, 1)
	joined := &observedCacheContext{Context: context.Background(), entered: make(chan struct{})}
	go func() {
		value, _ := cache.get(joined, "key", true, time.Minute, time.Second, load)
		second <- value
	}()
	<-joined.entered
	cancel()
	if err := <-first; !errors.Is(err, context.Canceled) {
		t.Fatalf("subscriber error = %v", err)
	}
	close(release)
	if value := <-second; value != 42 {
		t.Fatalf("remaining subscriber = %d", value)
	}
	if value, err := cache.get(context.Background(), "key", false, time.Minute, time.Second, load); value != 42 || err != nil || calls.Load() != 1 {
		t.Fatal("warm read started another operation")
	}
}

func TestReadCacheProxyChangesFreshReadsAndInvalidation(t *testing.T) {
	var cache readCache[int]
	var calls int
	load := func(context.Context) (int, error) { calls++; return calls, nil }
	get := func(key string, fresh bool) int {
		value, err := cache.get(context.Background(), key, fresh, time.Minute, time.Second, load)
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	if get("first-proxy", false) != 1 || get("first-proxy", false) != 1 || get("second-proxy", false) != 2 || get("second-proxy", true) != 3 {
		t.Fatal("cache ignored proxy or fresh request")
	}
	cache.invalidateFor("finished-task")
	if get("second-proxy", false) != 4 {
		t.Fatal("task completion did not invalidate")
	}
	cache.invalidateFor("finished-task")
	if get("second-proxy", false) != 4 {
		t.Fatal("same task status invalidated again")
	}
}

func TestReadCacheInvalidationCannotPublishOldFlight(t *testing.T) {
	var cache readCache[int]
	var calls atomic.Int32
	entered, release := make(chan struct{}), make(chan struct{})
	load := func(context.Context) (int, error) {
		n := calls.Add(1)
		if n == 1 {
			close(entered)
			<-release
		}
		return int(n), nil
	}
	done := make(chan int, 1)
	go func() {
		value, _ := cache.get(context.Background(), "key", false, time.Minute, time.Second, load)
		done <- value
	}()
	<-entered
	cache.invalidateFor("completed")
	close(release)
	if value := <-done; value != 2 {
		t.Fatalf("stale invalidated flight = %d", value)
	}
}

func TestReadCacheDeadlineAndFailureRetry(t *testing.T) {
	var cache readCache[int]
	load := func(ctx context.Context) (int, error) { <-ctx.Done(); return 0, ctx.Err() }
	_, err := cache.get(context.Background(), "key", false, time.Minute, time.Millisecond, load)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("deadline = %v", err)
	}
	value, err := cache.get(context.Background(), "key", true, time.Minute, time.Second, func(context.Context) (int, error) { return 7, nil })
	if value != 7 || err != nil {
		t.Fatal("explicit retry reused cached failure")
	}
}
