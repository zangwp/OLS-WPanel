package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func TestDashboardResourceMappingAndTotals(t *testing.T) {
	db := dashboardTestDB(t)
	if _, err := db.Exec(`INSERT INTO websites(id,domain,system_user) VALUES(1,'one.example','wp_one'),(2,'two.example','php_two'),(3,'idle.example','wp_idle')`); err != nil {
		t.Fatal(err)
	}
	processes := []byte("USER %CPU %MEM COMMAND\nwp_one 2.5 1.2 lsphp\nwp_one 3.5 2.3 lsphp8.5\nwp_one 90 30 bash\nphp_two 8.0 4.0 LSPHP\nwp_unknown 99 99 lsphp\nroot 70 20 lsphp\n")
	var calls atomic.Int32
	read := func(context.Context) ([]byte, error) { calls.Add(1); return processes, nil }
	cache := newSiteResourceCache(func(ctx context.Context) ([]siteResource, error) { return sampleSiteResources(ctx, db, read) })
	var group sync.WaitGroup
	errorsFound := make(chan error, 20)
	for i := 0; i < 20; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			snapshot, _, err := cache.get(context.Background(), false)
			if err != nil {
				errorsFound <- err
				return
			}
			if len(snapshot.Sites) != 2 || snapshot.Sites[0].SiteID != 2 || snapshot.Sites[0].CPU != 8 || snapshot.Sites[1].CPU != 6 || snapshot.Sites[1].Mem != 3.5 || snapshot.Sites[1].ProcCount != 2 {
				errorsFound <- errors.New("incorrect mapping, ordering or process totals")
			}
		}()
	}
	group.Wait()
	close(errorsFound)
	for err := range errorsFound {
		t.Error(err)
	}
	if calls.Load() != 1 {
		t.Fatalf("shared sample ran %d process scans", calls.Load())
	}
	if _, err := sampleSiteResources(context.Background(), db, func(context.Context) ([]byte, error) { return []byte("wp_one NaN 1 lsphp"), nil }); err == nil {
		t.Fatal("invalid metrics became zero")
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := sampleSiteResources(context.Background(), db, read); err == nil {
		t.Fatal("mapping failure became successful empty data")
	}
}

func TestDashboardResourceCacheTTLAndFreshSemantics(t *testing.T) {
	now := time.Date(2026, 10, 11, 8, 0, 0, 0, time.UTC)
	var calls atomic.Int32
	cache := newSiteResourceCache(func(context.Context) ([]siteResource, error) {
		n := calls.Add(1)
		return []siteResource{{SiteID: int(n), Domain: "one.example"}}, nil
	})
	cache.now = func() time.Time { return now }
	first, cached, err := cache.get(context.Background(), false)
	if err != nil || cached || first.SampledAt != now {
		t.Fatalf("first snapshot: %+v %v %v", first, cached, err)
	}
	now = now.Add(siteResourceCacheTTL - time.Nanosecond)
	second, cached, err := cache.get(context.Background(), false)
	if err != nil || !cached || second.SampledAt != first.SampledAt || calls.Load() != 1 {
		t.Fatal("valid cache was re-sampled or re-dated")
	}
	now = now.Add(time.Nanosecond)
	if _, cached, err := cache.get(context.Background(), false); err != nil || cached || calls.Load() != 2 {
		t.Fatal("expired snapshot was not refreshed")
	}
	if _, cached, err := cache.get(context.Background(), true); err != nil || cached || calls.Load() != 3 {
		t.Fatal("fresh did not bypass completed cache")
	}
	cache.load = func(context.Context) ([]siteResource, error) { return nil, errors.New("ps failed") }
	if _, _, err := cache.get(context.Background(), true); err == nil {
		t.Fatal("sampling failure reported success")
	}
	now = now.Add(siteResourceCacheTTL)
	if _, _, err := cache.get(context.Background(), false); err == nil {
		t.Fatal("failure renewed previous snapshot TTL")
	}
}

func TestDashboardResourceWaiterCancellationDoesNotCancelSharedSample(t *testing.T) {
	started := make(chan context.Context, 1)
	release := make(chan struct{})
	var calls atomic.Int32
	cache := newSiteResourceCache(func(ctx context.Context) ([]siteResource, error) {
		calls.Add(1)
		started <- ctx
		select {
		case <-release:
			return []siteResource{{Domain: "one.example"}}, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	})
	firstCtx, cancel := context.WithCancel(context.Background())
	firstResult := make(chan error, 1)
	go func() { _, _, err := cache.get(firstCtx, true); firstResult <- err }()
	sharedCtx := <-started
	secondCtx := &dashboardObservedContext{Context: context.Background(), entered: make(chan struct{})}
	secondResult := make(chan error, 1)
	go func() { _, _, err := cache.get(secondCtx, true); secondResult <- err }()
	<-secondCtx.entered
	cancel()
	if err := <-firstResult; !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled waiter=%v", err)
	}
	if sharedCtx.Err() != nil {
		t.Fatal("one waiter cancelled other tabs' sampling")
	}
	close(release)
	if err := <-secondResult; err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatalf("in-progress fresh calls were not coalesced: %d", calls.Load())
	}
}

type dashboardObservedContext struct {
	context.Context
	entered chan struct{}
	once    sync.Once
}

func (c *dashboardObservedContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.entered) })
	return c.Context.Done()
}

func TestDashboardResourceSharedTimeoutAndOutputLimit(t *testing.T) {
	cache := newSiteResourceCache(func(ctx context.Context) ([]siteResource, error) { <-ctx.Done(); return nil, ctx.Err() })
	cache.timeout = 20 * time.Millisecond
	if _, _, err := cache.get(context.Background(), false); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("timeout=%v", err)
	}
	var buffer siteProcessBuffer
	if _, err := buffer.Write(make([]byte, siteResourceOutputLimit)); err != nil {
		t.Fatal(err)
	}
	if n, err := buffer.Write([]byte{1}); err == nil || n != 0 || buffer.Len() != siteResourceOutputLimit {
		t.Fatal("process output limit not enforced")
	}
	var copied siteProcessBuffer
	// os/exec copies stdout through io.Copy. A promoted bytes.Buffer.ReadFrom
	// would bypass Write's limit, so verify the actual copy path too.
	if _, err := io.Copy(&copied, io.LimitReader(bytes.NewReader(make([]byte, siteResourceOutputLimit+1)), siteResourceOutputLimit+1)); err == nil || copied.Len() > siteResourceOutputLimit {
		t.Fatal("stdout copy bypassed output limit")
	}
}

func TestDashboardResourceHTTPKeepsArrayAndReportsSampleTime(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cache := newSiteResourceCache(func(context.Context) ([]siteResource, error) {
		return []siteResource{{SiteID: 1, Domain: "one.example", CPU: 5}}, nil
	})
	handler := &DashboardHandler{resources: cache}
	router := gin.New()
	router.GET("/resources", handler.GetSiteResources)
	request := func(url string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, url, nil))
		return rec
	}
	var body struct {
		Success   bool           `json:"success"`
		Data      []siteResource `json:"data"`
		SampledAt string         `json:"sampled_at"`
		Cached    bool           `json:"cached"`
		TTL       int            `json:"cache_ttl_seconds"`
	}
	first := request("/resources")
	if first.Code != http.StatusOK || json.Unmarshal(first.Body.Bytes(), &body) != nil || !body.Success || len(body.Data) != 1 || body.SampledAt == "" || body.TTL != 15 {
		t.Fatalf("unexpected response: %s", first.Body.String())
	}
	if second := request("/resources"); json.Unmarshal(second.Body.Bytes(), &body) != nil || !body.Cached {
		t.Fatalf("cache metadata missing: %s", second.Body.String())
	}
	if invalid := request("/resources?fresh=invalid"); invalid.Code != http.StatusBadRequest {
		t.Fatal("invalid fresh accepted")
	}
	cache.load = func(context.Context) ([]siteResource, error) { return nil, errors.New("ps failed") }
	failed := request("/resources?fresh=1")
	if failed.Code != http.StatusInternalServerError {
		t.Fatalf("failed sampler returned %d", failed.Code)
	}
	var failure map[string]any
	if err := json.Unmarshal(failed.Body.Bytes(), &failure); err != nil || failure["success"] != false || failure["data"] != nil {
		t.Fatalf("failure fabricated resource values: %s", failed.Body.String())
	}
}
