package executor

import (
	"context"
	"time"
)

// Summary and interactive detail scans share a process-wide I/O limit.
// Waiting for a slot also obeys the request's deadline/cancellation.
var logAnalysisScanSlots = make(chan struct{}, 2)

const logAnalysisScanTimeout = 30 * time.Second
const logAnalysisDetailMaxBytes = int64(64 * 1024 * 1024)

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
