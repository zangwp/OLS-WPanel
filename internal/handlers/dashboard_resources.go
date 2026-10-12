package handlers

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"io"
	"math"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	siteResourceCacheTTL      = 15 * time.Second
	siteResourceSampleTimeout = 5 * time.Second
	siteResourceOutputLimit   = 8 << 20
)

type siteResource struct {
	SiteID    int     `json:"site_id"`
	Domain    string  `json:"domain"`
	CPU       float64 `json:"cpu"`
	Mem       float64 `json:"mem"`
	ProcCount int     `json:"proc_count"`
}

type siteResourceSnapshot struct {
	Sites     []siteResource
	SampledAt time.Time
}

type siteResourceFlight struct {
	done     chan struct{}
	snapshot siteResourceSnapshot
	err      error
}

type siteResourceCache struct {
	mu       sync.Mutex
	load     func(context.Context) ([]siteResource, error)
	now      func() time.Time
	ttl      time.Duration
	timeout  time.Duration
	expires  time.Time
	snapshot siteResourceSnapshot
	flight   *siteResourceFlight
}

func newSiteResourceCache(load func(context.Context) ([]siteResource, error)) *siteResourceCache {
	return &siteResourceCache{load: load, now: time.Now, ttl: siteResourceCacheTTL, timeout: siteResourceSampleTimeout}
}

// fresh bypasses a completed snapshot, but joins an already-running sample.
// A caller only cancels its own wait. The shared sample has its own five-second
// deadline so another tab cannot interrupt the other waiters' process query.
func (s *siteResourceCache) get(ctx context.Context, fresh bool) (siteResourceSnapshot, bool, error) {
	if err := ctx.Err(); err != nil {
		return siteResourceSnapshot{}, false, err
	}
	s.mu.Lock()
	if !fresh && s.now().Before(s.expires) {
		snapshot := s.snapshot
		s.mu.Unlock()
		return snapshot, true, nil
	}
	flight := s.flight
	if flight == nil {
		flight = &siteResourceFlight{done: make(chan struct{})}
		s.flight = flight
		go s.run(flight)
	}
	s.mu.Unlock()
	select {
	case <-ctx.Done():
		return siteResourceSnapshot{}, false, ctx.Err()
	case <-flight.done:
		if err := ctx.Err(); err != nil {
			return siteResourceSnapshot{}, false, err
		}
		return flight.snapshot, false, flight.err
	}
}

func (s *siteResourceCache) run(flight *siteResourceFlight) {
	ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()
	sites, err := s.load(ctx)
	if err == nil {
		err = ctx.Err()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	flight.err = err
	if err == nil {
		if sites == nil {
			sites = []siteResource{}
		}
		flight.snapshot = siteResourceSnapshot{Sites: sites, SampledAt: s.now().UTC()}
		s.snapshot = flight.snapshot
		s.expires = flight.snapshot.SampledAt.Add(s.ttl)
	}
	// Errors do not renew an old snapshot or publish an empty successful result.
	s.flight = nil
	close(flight.done)
}

type siteProcessBuffer struct{ buffer bytes.Buffer }

func (b *siteProcessBuffer) Len() int      { return b.buffer.Len() }
func (b *siteProcessBuffer) Bytes() []byte { return b.buffer.Bytes() }

func (b *siteProcessBuffer) Write(p []byte) (int, error) {
	if len(p) > siteResourceOutputLimit-b.Len() {
		return 0, errors.New("site process output exceeds limit")
	}
	return b.buffer.Write(p)
}

func readSiteProcessOutput(ctx context.Context) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "ps", "-eo", "user:32,%cpu,%mem,comm")
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	var output siteProcessBuffer
	cmd.Stdout = &output
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

func sampleSiteResources(ctx context.Context, db *sql.DB, readProcesses func(context.Context) ([]byte, error)) ([]siteResource, error) {
	if db == nil {
		return nil, errors.New("site resources database unavailable")
	}
	out, err := readProcesses(ctx)
	if err != nil {
		return nil, err
	}
	agg := make(map[string]*siteResource)
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		user := fields[0]
		if (!strings.HasPrefix(user, "wp_") && !strings.HasPrefix(user, "php_")) || !strings.HasPrefix(strings.ToLower(fields[3]), "lsphp") {
			continue
		}
		cpu, err := strconv.ParseFloat(fields[1], 64)
		if err != nil || math.IsNaN(cpu) || math.IsInf(cpu, 0) || cpu < 0 {
			return nil, errors.New("invalid process CPU sample")
		}
		mem, err := strconv.ParseFloat(fields[2], 64)
		if err != nil || math.IsNaN(mem) || math.IsInf(mem, 0) || mem < 0 {
			return nil, errors.New("invalid process memory sample")
		}
		if agg[user] == nil {
			agg[user] = &siteResource{}
		}
		agg[user].CPU += cpu
		agg[user].Mem += mem
		agg[user].ProcCount++
	}
	// One mapping query replaces a separate lookup for every PHP user.
	rows, err := db.QueryContext(ctx, "SELECT id, domain, system_user FROM websites ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []siteResource{}
	seen := make(map[string]bool)
	for rows.Next() {
		var id int
		var domain, user string
		if err := rows.Scan(&id, &domain, &user); err != nil {
			return nil, err
		}
		if sr := agg[user]; sr != nil && !seen[user] && domain != "" {
			sr.SiteID, sr.Domain = id, domain
			result = append(result, *sr)
			seen[user] = true
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].CPU != result[j].CPU {
			return result[i].CPU > result[j].CPU
		}
		return result[i].SiteID < result[j].SiteID
	})
	return result, nil
}
