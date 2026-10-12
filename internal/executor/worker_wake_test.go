package executor

import (
	"context"
	"testing"
	"time"
)

func TestWorkerIdlePollBackoffAndWake(t *testing.T) {
	wake := make(chan struct{}, 1)
	poll := newWorkerIdlePoll(time.Millisecond, wake)
	for i := 0; i < 7; i++ {
		if !poll.wait(context.Background()) {
			t.Fatal("unexpected stop")
		}
	}
	if poll.next != 30*time.Millisecond {
		t.Fatalf("idle maximum = %v", poll.next)
	}
	signalWorker(wake)
	signalWorker(wake) // A burst cannot block admission or grow a signal queue.
	if len(wake) != 1 {
		t.Fatal("wake-ups were not coalesced")
	}
	if !poll.wait(context.Background()) || poll.next != time.Millisecond {
		t.Fatal("wake did not reset the idle delay")
	}
	poll.next = poll.maximum
	poll.reset()
	if poll.next != poll.base {
		t.Fatal("work did not reset the idle delay")
	}
}

func TestWorkerIdlePollCancellationAndProductionBound(t *testing.T) {
	poll := newWorkerIdlePoll(time.Second, make(chan struct{}, 1))
	if poll.maximum != 30*time.Second {
		t.Fatalf("maximum = %v", poll.maximum)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if poll.wait(ctx) {
		t.Fatal("cancelled worker kept polling")
	}
}
