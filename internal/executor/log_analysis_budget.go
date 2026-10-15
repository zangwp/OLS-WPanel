package executor

import (
	"context"
	"strings"
	"time"
)

// Summary and interactive detail scans share a process-wide I/O limit.
// Waiting for a slot also obeys the request's deadline/cancellation.
var logAnalysisScanSlots = make(chan struct{}, 2)

const logAnalysisScanTimeout = 30 * time.Second
const logAnalysisDetailMaxBytes = int64(64 * 1024 * 1024)

// Reading a bounded log is not enough to bound aggregation: distinct paths,
// IPs and request deduplication keys can otherwise retain most of the input.
// These budgets belong to one complete analysis, including rotated files.
const logAnalysisMaxAggregationKeys = 100000
const logAnalysisMaxAggregationKeyBytes = 16 * 1024 * 1024

type logAggregationBudget struct {
	keys     int
	keyBytes int
}

func (b *logAggregationBudget) reserve(keys []string) bool {
	bytes := 0
	for _, key := range keys {
		bytes += len(key)
	}
	if len(keys) > logAnalysisMaxAggregationKeys-b.keys || bytes > logAnalysisMaxAggregationKeyBytes-b.keyBytes {
		return false
	}
	b.keys += len(keys)
	b.keyBytes += bytes
	return true
}

func appendNewLogAggregationKey[V any](keys []string, values map[string]V, key string) []string {
	if _, exists := values[key]; !exists {
		return append(keys, key)
	}
	return keys
}

// Go regexp captures and URL paths may point into the full input line. Copy
// retained keys even on replacement so a small IP/path cannot pin a long UA.
func incrementLogAggregation(values map[string]int, key string) {
	values[strings.Clone(key)]++
}

func retainLogAggregationKey(values map[string]struct{}, key string) {
	if _, exists := values[key]; !exists {
		values[strings.Clone(key)] = struct{}{}
	}
}

func acquireLogAnalysisScan(ctx context.Context) (context.Context, func(), error) {
	ctx, cancel := context.WithTimeout(ctx, logAnalysisScanTimeout)
	select {
	case logAnalysisScanSlots <- struct{}{}:
		if err := ctx.Err(); err != nil {
			<-logAnalysisScanSlots
			cancel()
			return nil, nil, err
		}
		return ctx, func() { <-logAnalysisScanSlots; cancel() }, nil
	case <-ctx.Done():
		cancel()
		return nil, nil, ctx.Err()
	}
}
