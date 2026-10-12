package handlers

import (
	"context"
	"os/exec"
	"strings"
	"sync"
	"time"
)

type softwareProbeRunner func(context.Context, string, ...string) ([]byte, error)

type softwareProbeResult struct {
	output  string
	err     error
	expires time.Time
}

type softwareProbeKey struct {
	command    string
	generation uint64
}

type softwareProbeFlight struct {
	done   chan struct{}
	result softwareProbeResult
}

// Only raw read-only command results are shared. Translations, configuration
// file values and the service guard's live runtime snapshot remain outside.
type softwareProbeCache struct {
	mu         sync.Mutex
	entries    map[string]softwareProbeResult
	flights    map[softwareProbeKey]*softwareProbeFlight
	generation uint64
	workers    chan struct{}
	run        softwareProbeRunner
	ttl        time.Duration
	timeout    time.Duration
}

func newSoftwareProbeCache(run softwareProbeRunner) *softwareProbeCache {
	return &softwareProbeCache{
		entries: make(map[string]softwareProbeResult), flights: make(map[softwareProbeKey]*softwareProbeFlight),
		workers: make(chan struct{}, 4), run: run, ttl: 30 * time.Second, timeout: 4 * time.Second,
	}
}

func boundedSoftwareRead(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.WaitDelay = time.Second
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if err != nil {
		return nil, err // Partial stderr/stdout is never an installed version.
	}
	return out, nil
}

var softwareReadCache = newSoftwareProbeCache(boundedSoftwareRead)

func (cache *softwareProbeCache) invalidate() {
	cache.mu.Lock()
	cache.generation++
	cache.entries = make(map[string]softwareProbeResult)
	cache.mu.Unlock()
}

func (cache *softwareProbeCache) read(ctx context.Context, fresh bool, name string, args ...string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	key := name + "\x00" + strings.Join(args, "\x00")
	cache.mu.Lock()
	if result, ok := cache.entries[key]; !fresh && ok && time.Now().Before(result.expires) {
		cache.mu.Unlock()
		return result.output, result.err
	}
	flightKey := softwareProbeKey{command: key, generation: cache.generation}
	flight := cache.flights[flightKey]
	if flight == nil {
		flight = &softwareProbeFlight{done: make(chan struct{})}
		cache.flights[flightKey] = flight
		// A caller's navigation/cancellation must not cancel a shared probe
		// being awaited by other requests. Its own short server deadline does.
		go cache.collect(flightKey, flight, name, append([]string(nil), args...))
	}
	cache.mu.Unlock()
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case <-flight.done:
		return flight.result.output, flight.result.err
	}
}

func (cache *softwareProbeCache) collect(key softwareProbeKey, flight *softwareProbeFlight, name string, args []string) {
	ctx, cancel := context.WithTimeout(context.Background(), cache.timeout)
	defer cancel()
	var result softwareProbeResult
	select {
	case cache.workers <- struct{}{}:
		output, err := cache.run(ctx, name, args...)
		<-cache.workers
		result.err = err
		if err == nil {
			result.output = strings.TrimSpace(string(output))
		}
	case <-ctx.Done():
		result.err = ctx.Err()
	}
	ttl := cache.ttl
	if result.err != nil {
		ttl = time.Second // Briefly coalesce failures; do not hide recovery for 30s.
	}
	result.expires = time.Now().Add(ttl)
	cache.mu.Lock()
	flight.result = result
	if key.generation == cache.generation {
		cache.entries[key.command] = result
	}
	delete(cache.flights, key)
	close(flight.done)
	cache.mu.Unlock()
}
