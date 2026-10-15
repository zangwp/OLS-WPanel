package housekeeping

import (
	"errors"
	"testing"
	"time"
)

func TestCleanupKeepsHalfHourlyCadenceAndDoesNotCatchUp(t *testing.T) {
	var schedule Cleanup
	start := time.Date(2026, 10, 15, 0, 0, 0, 0, time.UTC)
	calls := 0
	clean := func() error { calls++; return nil }
	for minute := 0; minute < 24*60; minute++ {
		if err := schedule.Run(start.Add(time.Duration(minute)*time.Minute), clean); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 48 {
		t.Fatalf("daily sweeps = %d, want 48 while worker still ticks every minute", calls)
	}
	later := start.Add(72 * time.Hour)
	if err := schedule.Run(later, clean); err != nil {
		t.Fatal(err)
	}
	if err := schedule.Run(later.Add(time.Minute), clean); err != nil {
		t.Fatal(err)
	}
	if calls != 49 {
		t.Fatalf("delayed worker replayed missed sweeps: %d", calls)
	}
}

func TestCleanupRetriesFailureOnNextWorkerTick(t *testing.T) {
	var schedule Cleanup
	start := time.Date(2026, 10, 15, 0, 0, 0, 0, time.UTC)
	wantErr := errors.New("database busy")
	if err := schedule.Run(start, func() error { return wantErr }); !errors.Is(err, wantErr) {
		t.Fatalf("cleanup error = %v", err)
	}
	calls := 0
	clean := func() error { calls++; return nil }
	if err := schedule.Run(start.Add(time.Minute), clean); err != nil {
		t.Fatal(err)
	}
	if err := schedule.Run(start.Add(30*time.Minute), clean); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("successful retry did not establish its own interval: %d", calls)
	}
	if err := schedule.Run(start.Add(31*time.Minute), clean); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("exact deadline did not run cleanup: %d", calls)
	}
}
