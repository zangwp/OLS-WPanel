package handlers

import (
	"context"
	"database/sql"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestMetricHistoryCacheSharesQueriesAcrossTabsAndKeepsCanceledWaitersIndependent(t *testing.T) {
	started, finish := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	cache := metricHistoryCache{load: func(ctx context.Context, _ *sql.DB, _ string, _ time.Time) (metricHistory, error) {
		calls.Add(1)
		close(started)
		<-finish
		return metricHistory{SampleCount: 2400, Displayed: 1000, Reduced: true}, ctx.Err()
	}}
	now := time.Date(2026, 10, 15, 8, 0, 10, 0, time.UTC)
	ctx, cancel := context.WithCancel(context.Background())
	first := make(chan error, 1)
	go func() { _, err := cache.get(ctx, nil, "15d", now); first <- err }()
	<-started
	cancel()
	if err := <-first; !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled tab: %v", err)
	}
	close(finish)
	for i := 0; i < 10; i++ {
		result, err := cache.get(context.Background(), nil, "15d", now.Add(time.Duration(i)*time.Second))
		if err != nil || result.SampleCount != 2400 || !result.Reduced {
			t.Fatalf("shared result=%+v err=%v", result, err)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("queried %d times in one collection minute", calls.Load())
	}
}

func TestMetricHistoryCacheRefreshesByMinuteRangeDatabaseAndDoesNotCacheFailure(t *testing.T) {
	var calls atomic.Int32
	fail := false
	cache := metricHistoryCache{load: func(_ context.Context, _ *sql.DB, _ string, _ time.Time) (metricHistory, error) {
		n := calls.Add(1)
		if fail {
			return metricHistory{}, errors.New("read failed")
		}
		return metricHistory{SampleCount: int(n)}, nil
	}}
	now := time.Date(2026, 10, 15, 8, 0, 10, 0, time.UTC)
	ctx := context.Background()
	for _, r := range []string{"24h", "7d", "15d"} {
		if _, err := cache.get(ctx, nil, r, now); err != nil {
			t.Fatal(err)
		}
	}
	if calls.Load() != 3 || len(cache.entries) != 3 {
		t.Fatal("ranges share an incorrect cache entry")
	}
	if _, err := cache.get(ctx, nil, "30d", now); err == nil || calls.Load() != 3 {
		t.Fatal("invalid range caused a query")
	}
	fail = true
	if _, err := cache.get(ctx, nil, "24h", now.Add(time.Minute)); err == nil {
		t.Fatal("failed refresh returned stale success")
	}
	fail = false
	result, err := cache.get(ctx, nil, "24h", now.Add(time.Minute))
	if err != nil || result.SampleCount != 5 {
		t.Fatalf("failure was cached: result=%+v err=%v", result, err)
	}
	if _, err := cache.get(ctx, new(sql.DB), "24h", now.Add(time.Minute)); err != nil || calls.Load() != 6 {
		t.Fatal("database replacement reused old history")
	}
}
