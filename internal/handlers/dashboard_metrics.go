package handlers

import (
	"context"
	"database/sql"
	"errors"
	"math"
	"sort"
	"time"
)

const (
	dashboardMetricPointLimit = 1200
	dashboardMetricTimeout    = 5 * time.Second
	// Six actual samples per time bucket preserve each series' min and max.
	// Two additional samples are reserved for the range's first and last.
	dashboardMetricBuckets = (dashboardMetricPointLimit - 2) / 6
)

type metricHistory struct {
	Labels        []string  `json:"labels"`
	CPU           []float64 `json:"cpu"`
	Memory        []float64 `json:"memory"`
	Load          []float64 `json:"load"`
	Timestamps    []string  `json:"timestamps"`
	SampleCount   int       `json:"sample_count"`
	Displayed     int       `json:"displayed_points"`
	PointLimit    int       `json:"point_limit"`
	Reduced       bool      `json:"reduced"`
	BucketSeconds int64     `json:"bucket_seconds"`
}

type metricSample struct {
	ID   int64
	Time time.Time
	CPU  float64
	Mem  float64
	Load float64
}

func metricRangeDuration(r string) (time.Duration, error) {
	switch r {
	case "24h":
		return 24 * time.Hour, nil
	case "7d":
		return 7 * 24 * time.Hour, nil
	case "15d":
		return 15 * 24 * time.Hour, nil
	default:
		return 0, errors.New("unsupported metrics range")
	}
}

// queryMetrics streams retained samples without keeping the complete history
// in memory. A short history is unchanged. Longer histories select the actual
// min/max samples of all three series in fixed time buckets, plus the endpoints;
// they never replace values with an average or fabricate simultaneous peaks.
func queryMetrics(ctx context.Context, db *sql.DB, r string, now time.Time) (metricHistory, error) {
	history := metricHistory{
		Labels: []string{}, CPU: []float64{}, Memory: []float64{}, Load: []float64{},
		Timestamps: []string{}, PointLimit: dashboardMetricPointLimit,
	}
	duration, err := metricRangeDuration(r)
	if err != nil {
		return history, err
	}
	if db == nil {
		return history, errors.New("metrics database unavailable")
	}
	ctx, cancel := context.WithTimeout(ctx, dashboardMetricTimeout)
	defer cancel()
	now = now.UTC().Truncate(time.Second)
	since := now.Add(-duration)
	seconds := int64(duration / time.Second)
	widthSeconds := (seconds + dashboardMetricBuckets - 1) / dashboardMetricBuckets
	width := time.Duration(widthSeconds) * time.Second
	rows, err := db.QueryContext(ctx, `SELECT id, recorded_at, cpu_percent, memory_percent, load_avg_1
		FROM monitoring_metrics WHERE recorded_at > ? AND recorded_at <= ?
		ORDER BY recorded_at ASC, id ASC`, since.Format("2006-01-02 15:04:05"), now.Format("2006-01-02 15:04:05"))
	if err != nil {
		return history, err
	}
	defer rows.Close()

	raw := make([]metricSample, 0, dashboardMetricPointLimit)
	selected := make([]metricSample, 0, dashboardMetricPointLimit)
	var extrema [6]metricSample
	var bucket int64 = -1
	var last metricSample
	appendSelected := func(point metricSample) {
		if len(selected) == 0 || selected[len(selected)-1].ID != point.ID {
			selected = append(selected, point)
		}
	}
	flushBucket := func() {
		if bucket < 0 {
			return
		}
		points := append([]metricSample(nil), extrema[:]...)
		sort.Slice(points, func(i, j int) bool {
			if !points[i].Time.Equal(points[j].Time) {
				return points[i].Time.Before(points[j].Time)
			}
			return points[i].ID < points[j].ID
		})
		for _, point := range points {
			appendSelected(point)
		}
	}
	for rows.Next() {
		var point metricSample
		if err := rows.Scan(&point.ID, &point.Time, &point.CPU, &point.Mem, &point.Load); err != nil {
			return history, err
		}
		if math.IsNaN(point.CPU) || math.IsInf(point.CPU, 0) || math.IsNaN(point.Mem) || math.IsInf(point.Mem, 0) || math.IsNaN(point.Load) || math.IsInf(point.Load, 0) {
			return history, errors.New("invalid monitoring sample")
		}
		history.SampleCount++
		if history.SampleCount <= dashboardMetricPointLimit {
			raw = append(raw, point)
		} else {
			raw = nil
		}
		nextBucket := int64(point.Time.Sub(since) / width)
		// The upper endpoint belongs to the final bucket, not a new one.
		if nextBucket >= dashboardMetricBuckets {
			nextBucket = dashboardMetricBuckets - 1
		}
		if nextBucket != bucket {
			flushBucket()
			bucket = nextBucket
			for i := range extrema {
				extrema[i] = point
			}
			if history.SampleCount == 1 {
				appendSelected(point)
			}
		} else {
			if point.CPU < extrema[0].CPU {
				extrema[0] = point
			}
			if point.CPU > extrema[1].CPU {
				extrema[1] = point
			}
			if point.Mem < extrema[2].Mem {
				extrema[2] = point
			}
			if point.Mem > extrema[3].Mem {
				extrema[3] = point
			}
			if point.Load < extrema[4].Load {
				extrema[4] = point
			}
			if point.Load > extrema[5].Load {
				extrema[5] = point
			}
		}
		last = point
	}
	if err := rows.Err(); err != nil {
		return history, err
	}
	flushBucket()
	if history.SampleCount > 0 {
		appendSelected(last)
	}
	points := raw
	if history.SampleCount > dashboardMetricPointLimit {
		points = selected
		history.Reduced = true
		history.BucketSeconds = widthSeconds
	}
	for _, point := range points {
		history.Labels = append(history.Labels, formatMetricLabel(point.Time, r))
		history.CPU = append(history.CPU, point.CPU)
		history.Memory = append(history.Memory, point.Mem)
		history.Load = append(history.Load, point.Load)
		// Match the server-local chart labels, including an explicit UTC offset
		// so the browser's local timezone cannot shift the tooltip's time.
		history.Timestamps = append(history.Timestamps, point.Time.Local().Format(time.RFC3339))
	}
	history.Displayed = len(points)
	return history, nil
}
