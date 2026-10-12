package executor

import (
	"context"
	"net/http"
	"sort"
	"sync"
	"time"
)

const siteAvailabilityConcurrency = 4
const siteAvailabilityBatchTimeout = 30 * time.Second

type siteAvailabilityTarget struct {
	id, domain, url string
	ssl             bool
	interval        int
}

type siteAvailabilityResult struct {
	id, domain string
	code       int
	err        error
	canceled   bool
	target     siteAvailabilityTarget
}

func checkSitesStateWithStop(stop <-chan struct{}) alertCheckResult {
	select {
	case <-stop:
		return unknownAlertCheck(context.Canceled)
	default:
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		select {
		case <-stop:
			cancel()
		case <-ctx.Done():
		}
	}()
	return checkSitesStateContext(ctx)
}

// Oldest completed observations go first. A batch-budget cancellation does not
// advance a site's timestamp, so later sites make progress on the next cycle.
func checkSiteAvailabilityTargets(ctx context.Context, client *http.Client, targets []siteAvailabilityTarget, lastCheck map[string]time.Time) ([]siteAvailabilityResult, bool) {
	sort.SliceStable(targets, func(i, j int) bool {
		return lastCheck[targets[i].id].Before(lastCheck[targets[j].id])
	})
	jobs := make(chan siteAvailabilityTarget)
	results := make(chan siteAvailabilityResult, siteAvailabilityConcurrency)
	var workers sync.WaitGroup
	for i := 0; i < siteAvailabilityConcurrency && i < len(targets); i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for target := range jobs {
				if ctx.Err() != nil {
					return
				}
				result := siteAvailabilityResult{id: target.id, domain: target.domain, target: target}
				request, err := http.NewRequestWithContext(ctx, http.MethodGet, target.url, nil)
				if err == nil {
					var response *http.Response
					response, err = client.Do(request)
					if err == nil {
						result.code = response.StatusCode
						_ = response.Body.Close()
					}
				}
				result.err, result.canceled = err, err != nil && ctx.Err() != nil
				results <- result
			}
		}()
	}
	go func() {
		defer close(jobs)
		for _, target := range targets {
			select {
			case jobs <- target:
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() { workers.Wait(); close(results) }()
	collected := make([]siteAvailabilityResult, 0, len(targets))
	for result := range results {
		collected = append(collected, result)
	}
	return collected, ctx.Err() == nil && len(collected) == len(targets)
}
