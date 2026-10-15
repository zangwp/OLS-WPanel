// Package housekeeping schedules low-frequency maintenance on existing workers.
package housekeeping

import "time"

const CleanupInterval = time.Hour

// Cleanup limits successful retention sweeps to once per hour. Its zero value
// is ready for the first sweep. Keep it local to a single serial worker: it
// starts no goroutine and does not synchronize concurrent callers.
type Cleanup struct {
	next time.Time
}

// Run executes clean when due. A failed sweep remains due so the worker's next
// ordinary tick retries it. A delayed worker performs one sweep, not a backlog.
func (c *Cleanup) Run(now time.Time, clean func() error) error {
	if !c.next.IsZero() && now.Before(c.next) {
		return nil
	}
	if err := clean(); err != nil {
		return err
	}
	c.next = now.Add(CleanupInterval)
	return nil
}
