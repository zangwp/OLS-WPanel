package executor

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestSiteAvailabilityBoundsActiveRequestsAndCompletesEveryTarget(t *testing.T) {
	var active, peak atomic.Int32
	first := make(chan struct{}, siteAvailabilityConcurrency)
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := active.Add(1)
		defer active.Add(-1)
		for old := peak.Load(); n > old; old = peak.Load() {
			if peak.CompareAndSwap(old, n) {
				break
			}
		}
		select {
		case first <- struct{}{}:
		default:
		}
		select {
		case <-release:
			w.WriteHeader(http.StatusOK)
		case <-r.Context().Done():
		}
	}))
	defer server.Close()
	defer unblock()
	client := newSiteAvailabilityHTTPClient()
	defer client.CloseIdleConnections()
	var targets []siteAvailabilityTarget
	for i := 0; i < 32; i++ {
		targets = append(targets, siteAvailabilityTarget{id: fmt.Sprint(i), url: server.URL})
	}
	done := make(chan []siteAvailabilityResult, 1)
	go func() {
		results, complete := checkSiteAvailabilityTargets(context.Background(), client, targets, nil)
		if !complete {
			results = nil
		}
		done <- results
	}()
	for i := 0; i < siteAvailabilityConcurrency; i++ {
		select {
		case <-first:
		case <-time.After(2 * time.Second):
			t.Fatal("workers did not enter local HTTP check")
		}
	}
	if got := peak.Load(); got != siteAvailabilityConcurrency {
		t.Fatalf("active requests=%d, want %d", got, siteAvailabilityConcurrency)
	}
	unblock()
	select {
	case results := <-done:
		if len(results) != len(targets) {
			t.Fatalf("completed=%d, want %d", len(results), len(targets))
		}
		for _, result := range results {
			if result.code != http.StatusOK || result.err != nil || result.canceled {
				t.Fatalf("invalid observation: %+v", result)
			}
		}
	case <-time.After(3 * time.Second):
		t.Fatal("bounded workers did not complete all sites")
	}
	if peak.Load() > siteAvailabilityConcurrency {
		t.Fatal("worker pool exceeded its concurrency limit")
	}
}

func TestSiteAvailabilityCancellationDoesNotStartQueuedRequests(t *testing.T) {
	entered := make(chan struct{}, siteAvailabilityConcurrency)
	var started atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started.Add(1)
		entered <- struct{}{}
		<-r.Context().Done()
	}))
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client := newSiteAvailabilityHTTPClient()
	defer client.CloseIdleConnections()
	var targets []siteAvailabilityTarget
	for i := 0; i < 20; i++ {
		targets = append(targets, siteAvailabilityTarget{id: fmt.Sprint(i), url: server.URL})
	}
	done := make(chan bool, 1)
	go func() {
		results, complete := checkSiteAvailabilityTargets(ctx, client, targets, nil)
		canceled := !complete
		for _, r := range results {
			canceled = canceled && r.canceled && r.code == 0
		}
		done <- canceled
	}()
	for i := 0; i < siteAvailabilityConcurrency; i++ {
		select {
		case <-entered:
		case <-time.After(2 * time.Second):
			t.Fatal("initial requests not started")
		}
	}
	cancel()
	select {
	case canceled := <-done:
		if !canceled {
			t.Fatal("canceled batch reported complete or a real failure")
		}
	case <-time.After(time.Second):
		t.Fatal("shutdown did not cancel requests promptly")
	}
	if got := started.Load(); got != siteAvailabilityConcurrency {
		t.Fatalf("started=%d, canceled queued sites must not execute", got)
	}
}

func TestSiteAvailabilityOldestUncheckedSitesGoFirst(t *testing.T) {
	entered := make(chan string, siteAvailabilityConcurrency)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		entered <- strings.TrimPrefix(r.URL.Path, "/")
		<-r.Context().Done()
	}))
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client := newSiteAvailabilityHTTPClient()
	defer client.CloseIdleConnections()
	var targets []siteAvailabilityTarget
	last := make(map[string]time.Time)
	for i := 0; i < 8; i++ {
		id := fmt.Sprint(i)
		targets = append(targets, siteAvailabilityTarget{id: id, url: server.URL + "/" + id})
		if i < 4 {
			last[id] = time.Now()
		}
	}
	done := make(chan struct{})
	go func() { checkSiteAvailabilityTargets(ctx, client, targets, last); close(done) }()
	for i := 0; i < siteAvailabilityConcurrency; i++ {
		select {
		case id := <-entered:
			if !last[id].IsZero() {
				t.Fatalf("recently checked site %s ran before an unchecked site", id)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("unchecked sites did not start")
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("canceled batch did not finish")
	}
}

func TestSiteAvailabilityInterruptedCollectorKeepsPriorIncident(t *testing.T) {
	for _, mode := range []string{"deadline", "monitor-stop"} {
		t.Run(mode, func(t *testing.T) {
			db := openAlertTestDB(t)
			mustExec(t, db, `CREATE TABLE websites(id INTEGER PRIMARY KEY,domain TEXT,status TEXT,ssl_enabled INTEGER,monitoring_enabled INTEGER,monitoring_interval INTEGER)`)
			entered := make(chan struct{}, 1)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { entered <- struct{}{}; <-r.Context().Done() }))
			defer server.Close()
			if _, err := db.Exec(`INSERT INTO websites VALUES(1,?,'active',0,1,1)`, strings.TrimPrefix(server.URL, "http://")); err != nil {
				t.Fatal(err)
			}
			siteFailureCounts["1"] = siteFailureAlertThreshold
			siteFailureMessages["1"] = "prior confirmed incident"
			websiteAvailabilityObservations.RLock()
			previous, existed := websiteAvailabilityObservations.entries["1"]
			websiteAvailabilityObservations.RUnlock()
			t.Cleanup(func() {
				websiteAvailabilityObservations.Lock()
				defer websiteAvailabilityObservations.Unlock()
				if existed {
					websiteAvailabilityObservations.entries["1"] = previous
				} else {
					delete(websiteAvailabilityObservations.entries, "1")
				}
			})
			priorAt := time.Now().Add(-time.Minute)
			recordWebsiteAvailabilityObservation("1", strings.TrimPrefix(server.URL, "http://"), false, 1, 503, siteFailureAlertThreshold, priorAt)
			done := make(chan alertCheckResult, 1)
			if mode == "deadline" {
				ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
				defer cancel()
				go func() { done <- checkSitesStateContext(ctx) }()
			} else {
				stop := make(chan struct{})
				go func() { done <- checkSitesStateWithStop(stop) }()
				select {
				case <-entered:
					close(stop)
				case <-time.After(2 * time.Second):
					close(stop)
					t.Fatal("check did not start")
				}
			}
			select {
			case result := <-done:
				if result.state != alertCheckUnknown {
					t.Fatalf("interrupted check falsely resolved incident: %+v", result)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("interrupted collector did not finish")
			}
			if siteFailureCounts["1"] != siteFailureAlertThreshold || siteFailureMessages["1"] != "prior confirmed incident" || !siteLastCheck["1"].IsZero() {
				t.Fatal("cancellation changed failures or postponed the retry")
			}
			websiteAvailabilityObservations.RLock()
			observation := websiteAvailabilityObservations.entries["1"]
			websiteAvailabilityObservations.RUnlock()
			if !observation.checkedAt.Equal(priorAt) || observation.statusCode != 503 || observation.failures != siteFailureAlertThreshold {
				t.Fatal("interruption replaced prior real HTTP evidence")
			}
		})
	}
}

func TestSiteAvailabilityBoundedCollectorStillRequiresTwoFailuresAndSeesRecovery(t *testing.T) {
	db := openAlertTestDB(t)
	mustExec(t, db, `CREATE TABLE websites(id INTEGER PRIMARY KEY,domain TEXT,status TEXT,ssl_enabled INTEGER,monitoring_enabled INTEGER,monitoring_interval INTEGER)`)
	var response atomic.Int32
	response.Store(http.StatusServiceUnavailable)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(int(response.Load())) }))
	defer server.Close()
	if _, err := db.Exec(`INSERT INTO websites VALUES(1,?,'active',0,1,1)`, strings.TrimPrefix(server.URL, "http://")); err != nil {
		t.Fatal(err)
	}
	for i, want := range []alertCheckState{alertCheckUnknown, alertCheckFiring, alertCheckNormal} {
		delete(siteLastCheck, "1")
		if i == 2 {
			response.Store(http.StatusOK)
		}
		if result := checkSitesState(); result.state != want {
			t.Fatalf("check %d=%+v, want %v", i, result, want)
		}
	}
	if siteFailureCounts["1"] != 0 || siteFailureMessages["1"] != "" {
		t.Fatal("completed recovery retained failure evidence")
	}
}

func TestSiteAvailabilityStoppedMonitorDoesNotWaitForWarmup(t *testing.T) {
	previous := alertMgr
	alertMgr = &alertManager{stopCh: make(chan struct{})}
	defer func() { alertMgr = previous }()
	StopAlertMonitor()
	StopAlertMonitor()
	done := make(chan struct{})
	go func() { alertMgr.loop(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("stopped monitor waited for the 30-second warmup")
	}
	result := checkSitesStateWithStop(alertMgr.stopCh)
	if result.state != alertCheckUnknown {
		t.Fatalf("stopped monitor returned a healthy check: %+v", result)
	}
}
