package handlers

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/zangwp/OLS-WPanel/internal/executor"
)

const (
	softwareProbeOutputLimit = 512 * 1024
	softwareVersionProbeTTL  = 5 * time.Minute
)

var errSoftwareProbeOutputLimit = errors.New("software probe output exceeds limit")

type softwareProbeOutput struct {
	buffer   bytes.Buffer
	exceeded bool
}

func (output *softwareProbeOutput) Len() int      { return output.buffer.Len() }
func (output *softwareProbeOutput) Bytes() []byte { return output.buffer.Bytes() }

func (output *softwareProbeOutput) Write(data []byte) (int, error) {
	written := len(data)
	remaining := softwareProbeOutputLimit - output.Len()
	if len(data) > remaining {
		output.exceeded = true
		data = data[:remaining]
	}
	_, _ = output.buffer.Write(data)
	// Drain excess output until the short command deadline. Returning an error
	// here can strand the producer on a full pipe before exec.Wait completes.
	return written, nil
}

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
	mu            sync.Mutex
	entries       map[string]softwareProbeResult
	flights       map[softwareProbeKey]*softwareProbeFlight
	generation    uint64
	invalidatedBy string
	workers       chan struct{}
	run           softwareProbeRunner
	ttl           time.Duration
	timeout       time.Duration
	now           func() time.Time
}

func newSoftwareProbeCache(run softwareProbeRunner) *softwareProbeCache {
	return &softwareProbeCache{
		entries: make(map[string]softwareProbeResult), flights: make(map[softwareProbeKey]*softwareProbeFlight),
		workers: make(chan struct{}, 4), run: run, ttl: 30 * time.Second, timeout: 4 * time.Second, now: time.Now,
	}
}

func boundedSoftwareRead(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.WaitDelay = time.Second
	var output softwareProbeOutput
	cmd.Stdout, cmd.Stderr = &output, &output
	err := cmd.Run()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if output.exceeded {
		return nil, errSoftwareProbeOutputLimit
	}
	if err != nil {
		// Retain only a recognized startup diagnostic in a typed error. Partial
		// stderr/stdout must never become an installed version or raw API data.
		return nil, executor.WrapLSPHPHealthProbeError(err, output.Bytes())
	}
	return output.Bytes(), nil
}

var softwareReadCache = newSoftwareProbeCache(boundedSoftwareRead)

func (cache *softwareProbeCache) invalidate() {
	cache.mu.Lock()
	cache.generation++
	cache.entries = make(map[string]softwareProbeResult)
	cache.mu.Unlock()
}

// A detached system update can finish while its settings page is closed.
// Re-reading its same terminal status must not keep clearing warm probes.
func (cache *softwareProbeCache) invalidateFor(token string) {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if token == cache.invalidatedBy {
		return
	}
	cache.invalidatedBy = token
	cache.generation++
	cache.entries = make(map[string]softwareProbeResult)
}

// Classify by the complete command, rather than the requesting endpoint, so
// list and guard requests cannot give an identical probe different lifetimes.
// Module, PHP health, cron and APT reads retain the short default lifetime.
func softwareVersionProbe(name string, args []string) bool {
	if len(args) != 1 {
		return false
	}
	if args[0] == "-v" && name == executor.OpenLiteSpeedBinaryPath() {
		return true
	}
	if args[0] != "--version" {
		return false
	}
	switch name {
	case "mariadb", "redis-server", "nft", "fail2ban-client":
		return true
	default:
		return false
	}
}

func (cache *softwareProbeCache) read(ctx context.Context, fresh bool, name string, args ...string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	key := name + "\x00" + strings.Join(args, "\x00")
	cache.mu.Lock()
	if result, ok := cache.entries[key]; !fresh && ok && cache.now().Before(result.expires) {
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
	if softwareVersionProbe(name, args) {
		ttl = softwareVersionProbeTTL
	}
	if result.err != nil {
		ttl = time.Second // Briefly coalesce failures; do not hide recovery for 30s.
	}
	result.expires = cache.now().Add(ttl)
	cache.mu.Lock()
	flight.result = result
	if key.generation == cache.generation {
		cache.entries[key.command] = result
	}
	delete(cache.flights, key)
	close(flight.done)
	cache.mu.Unlock()
}
