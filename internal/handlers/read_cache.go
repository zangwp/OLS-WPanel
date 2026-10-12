package handlers

import (
	"context"
	"sync"
	"time"
)

// A completed snapshot is cached briefly. Concurrent refreshes share a bounded
// read, while cancelling one HTTP request does not cancel other subscribers.
type readCache[T any] struct {
	mu            sync.Mutex
	key           string
	value         T
	err           error
	expires       time.Time
	generation    uint64
	invalidatedBy string
	flight        *readCacheFlight[T]
}

type readCacheFlight[T any] struct {
	key        string
	generation uint64
	done       chan struct{}
	value      T
	err        error
}

func (cache *readCache[T]) get(ctx context.Context, key string, fresh bool, ttl, deadline time.Duration, load func(context.Context) (T, error)) (T, error) {
	var zero T
	for {
		if err := ctx.Err(); err != nil {
			return zero, err
		}
		cache.mu.Lock()
		if !fresh && cache.key == key && time.Now().Before(cache.expires) {
			value, err := cache.value, cache.err
			cache.mu.Unlock()
			return value, err
		}
		flight := cache.flight
		if flight == nil {
			flight = &readCacheFlight[T]{key: key, generation: cache.generation, done: make(chan struct{})}
			cache.flight = flight
			go func() {
				readCtx, cancel := context.WithTimeout(context.Background(), deadline)
				value, err := load(readCtx)
				cancel()
				cache.mu.Lock()
				flight.value, flight.err = value, err
				if flight.generation == cache.generation {
					cache.key, cache.value, cache.err = key, value, err
					duration := ttl
					if err != nil && duration > 10*time.Second {
						duration = 10 * time.Second
					}
					cache.expires = time.Now().Add(duration)
				}
				cache.flight = nil
				close(flight.done)
				cache.mu.Unlock()
			}()
		}
		cache.mu.Unlock()
		select {
		case <-ctx.Done():
			return zero, ctx.Err()
		case <-flight.done:
			cache.mu.Lock()
			valid := flight.generation == cache.generation
			cache.mu.Unlock()
			if flight.key == key && valid {
				return flight.value, flight.err
			}
		}
	}
}

// Re-reading the same terminal task must not invalidate every warm snapshot.
func (cache *readCache[T]) invalidateFor(token string) {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if token == cache.invalidatedBy {
		return
	}
	cache.invalidatedBy = token
	cache.generation++
	cache.expires = time.Time{}
}
