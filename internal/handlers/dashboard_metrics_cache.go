package handlers

import (
	"context"
	"database/sql"
	"sync"
	"time"
)

// History is collected once per minute. Share one bounded query per range and
// minute across tabs; preserve queryMetrics' actual-sample peak reduction.
type metricHistoryCache struct {
	mu      sync.Mutex
	entries map[string]*metricHistoryFlight
	load    func(context.Context, *sql.DB, string, time.Time) (metricHistory, error)
}

type metricHistoryFlight struct {
	done     chan struct{}
	db       *sql.DB
	minute   int64
	location *time.Location
	history  metricHistory
	err      error
}

func (s *metricHistoryCache) get(ctx context.Context, db *sql.DB, r string, now time.Time) (metricHistory, error) {
	if err := ctx.Err(); err != nil {
		return metricHistory{}, err
	}
	if _, err := metricRangeDuration(r); err != nil {
		return metricHistory{}, err
	}
	minute := now.Unix() / 60
	s.mu.Lock()
	if s.entries == nil {
		s.entries = make(map[string]*metricHistoryFlight, 3)
	}
	flight := s.entries[r]
	if flight == nil || flight.db != db || flight.minute != minute || flight.location != time.Local {
		flight = &metricHistoryFlight{done: make(chan struct{}), db: db, minute: minute, location: time.Local}
		s.entries[r] = flight
		load := s.load
		if load == nil {
			load = queryMetrics
		}
		go s.run(flight, r, now, load)
	}
	s.mu.Unlock()
	select {
	case <-ctx.Done():
		return metricHistory{}, ctx.Err()
	case <-flight.done:
		if err := ctx.Err(); err != nil {
			return metricHistory{}, err
		}
		return flight.history, flight.err
	}
}

func (s *metricHistoryCache) run(flight *metricHistoryFlight, r string, now time.Time, load func(context.Context, *sql.DB, string, time.Time) (metricHistory, error)) {
	// Closing a tab cancels only that tab's wait, not another tab's shared query.
	ctx, cancel := context.WithTimeout(context.Background(), dashboardMetricTimeout)
	defer cancel()
	history, err := load(ctx, flight.db, r, now)
	if err == nil {
		err = ctx.Err()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	flight.history, flight.err = history, err
	if err != nil && s.entries[r] == flight {
		// Do not cache errors or return stale history as a fresh successful read.
		delete(s.entries, r)
	}
	close(flight.done)
}
