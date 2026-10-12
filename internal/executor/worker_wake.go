package executor

import (
	"context"
	"time"
)

// The durable SQLite queue is authoritative. Wake-ups only reduce latency;
// a bounded poll still discovers commits from other processes or missed signals.
var wpInventoryWake = make(chan struct{}, 1)
var wpUpdateWake = make(chan struct{}, 1)

func signalWorker(wake chan struct{}) {
	select {
	case wake <- struct{}{}:
	default:
	}
}

type workerIdlePoll struct {
	base, next, maximum time.Duration
	wake                <-chan struct{}
}

func newWorkerIdlePoll(base time.Duration, wake <-chan struct{}) workerIdlePoll {
	maximum := 30 * base
	if maximum > 30*time.Second {
		maximum = 30 * time.Second
	}
	if maximum < base {
		maximum = base
	}
	return workerIdlePoll{base: base, next: base, maximum: maximum, wake: wake}
}

func (p *workerIdlePoll) reset() { p.next = p.base }

func (p *workerIdlePoll) wait(ctx context.Context) bool {
	timer := time.NewTimer(p.next)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-p.wake:
		p.reset()
		return true
	case <-timer.C:
		if p.next < p.maximum {
			p.next *= 2
			if p.next > p.maximum {
				p.next = p.maximum
			}
		}
		return true
	}
}
