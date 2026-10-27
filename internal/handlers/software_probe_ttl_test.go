package handlers

import (
	"context"
	"errors"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zangwp/OLS-WPanel/internal/executor"
)

func softwareProbeClock(cache *softwareProbeCache) func(time.Duration) {
	var elapsed atomic.Int64
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cache.now = func() time.Time { return base.Add(time.Duration(elapsed.Load())) }
	return func(duration time.Duration) { elapsed.Add(int64(duration)) }
}

func TestSoftwareServiceVersionsRemainCachedPastDynamicTTL(t *testing.T) {
	for _, command := range []string{executor.OpenLiteSpeedBinaryPath(), "mariadb", "redis-server", "nft", "fail2ban-client"} {
		t.Run(command, func(t *testing.T) {
			var calls atomic.Int32
			cache := newSoftwareProbeCache(func(context.Context, string, ...string) ([]byte, error) {
				return []byte(strconv.Itoa(int(calls.Add(1)))), nil
			})
			advance := softwareProbeClock(cache)
			arg := "--version"
			if command == executor.OpenLiteSpeedBinaryPath() {
				arg = "-v"
			}
			read := func(fresh bool, want string) {
				t.Helper()
				if output, err := cache.read(t.Context(), fresh, command, arg); err != nil || output != want {
					t.Fatalf("read(%v) = %q, %v; want %q", fresh, output, err, want)
				}
			}
			read(false, "1")
			advance(31 * time.Second)
			read(false, "1")
			advance(4*time.Minute + 28*time.Second)
			read(false, "1")
			advance(time.Second)
			read(false, "2")
			read(true, "3")
			cache.invalidate()
			read(false, "4")
			if calls.Load() != 4 {
				t.Fatalf("version command executions = %d; want 4", calls.Load())
			}
		})
	}
}

func TestSoftwareDynamicProbesRetainThirtySecondLifetime(t *testing.T) {
	for _, command := range []struct {
		name string
		args []string
	}{
		{"/usr/bin/env", []string{"-i", "PATH=/usr/bin:/bin", "PHP_INI_SCAN_DIR=/fixture/conf.d", "/fixture/lsphp", "-i"}},
		{executor.LSPHPBinaryPath(), []string{"-m"}},
		{executor.LSPHPBinaryPath(), []string{"-v"}},
		{"systemctl", []string{"show", "cron.service", "--property=LoadState,ActiveState,SubState,UnitFileState"}},
		{"apt-cache", []string{"policy", "redis-server"}},
		{"dpkg-query", []string{"-W", "-f=${Version}", "redis-server"}},
		{"redis-server", []string{"--version", "--another-option"}},
		{"redis-server", []string{"--help"}},
		{"unknown-version-command", []string{"--version"}},
	} {
		t.Run(command.name+"/"+strconv.Itoa(len(command.args)), func(t *testing.T) {
			var calls atomic.Int32
			cache := newSoftwareProbeCache(func(context.Context, string, ...string) ([]byte, error) {
				return []byte(strconv.Itoa(int(calls.Add(1)))), nil
			})
			advance := softwareProbeClock(cache)
			for _, want := range []string{"1", "1", "2"} {
				if output, err := cache.read(t.Context(), false, command.name, command.args...); err != nil || output != want {
					t.Fatalf("dynamic read = %q, %v; want %q", output, err, want)
				}
				advance(15 * time.Second)
			}
		})
	}
}

func TestSoftwareVersionFailureRetriesAfterOneSecond(t *testing.T) {
	var calls atomic.Int32
	cache := newSoftwareProbeCache(func(context.Context, string, ...string) ([]byte, error) {
		if calls.Add(1) == 1 {
			return []byte("untrusted partial version"), errors.New("temporary probe failure")
		}
		return []byte("recovered"), nil
	})
	advance := softwareProbeClock(cache)
	for range 2 {
		if output, err := cache.read(t.Context(), false, "redis-server", "--version"); err == nil || output != "" {
			t.Fatalf("failed version probe produced output: %q, %v", output, err)
		}
		advance(500 * time.Millisecond)
	}
	if calls.Load() != 1 {
		t.Fatalf("failure was not briefly coalesced: %d calls", calls.Load())
	}
	if output, err := cache.read(t.Context(), false, "redis-server", "--version"); err != nil || output != "recovered" || calls.Load() != 2 {
		t.Fatalf("version did not recover after 1s: %q, %v, calls=%d", output, err, calls.Load())
	}
}

func TestSoftwareTerminalInvalidationCannotRestoreOldVersionFlight(t *testing.T) {
	var calls atomic.Int32
	started, release, oldDone := make(chan struct{}), make(chan struct{}), make(chan struct{})
	cache := newSoftwareProbeCache(func(context.Context, string, ...string) ([]byte, error) {
		if calls.Add(1) == 1 {
			close(started)
			<-release
			return []byte("old"), nil
		}
		return []byte("new"), nil
	})
	go func() {
		_, _ = cache.read(t.Context(), false, "redis-server", "--version")
		close(oldDone)
	}()
	<-started
	cache.invalidateFor("system-update:finished")
	if output, err := cache.read(t.Context(), false, "redis-server", "--version"); err != nil || output != "new" {
		t.Fatalf("terminal update reused old flight: %q, %v", output, err)
	}
	close(release)
	<-oldDone
	cache.invalidateFor("system-update:finished")
	if output, err := cache.read(t.Context(), false, "redis-server", "--version"); err != nil || output != "new" || calls.Load() != 2 {
		t.Fatalf("old worker or repeated terminal status invalidated current result: %q, %v, calls=%d", output, err, calls.Load())
	}
}
