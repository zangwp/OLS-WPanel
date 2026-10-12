package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/zangwp/OLS-WPanel/internal/models"
	_ "modernc.org/sqlite"
)

func dashboardTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	for _, statement := range []string{
		`CREATE TABLE monitoring_metrics(id INTEGER PRIMARY KEY, recorded_at DATETIME NOT NULL, cpu_percent REAL, memory_percent REAL, load_avg_1 REAL)`,
		`CREATE INDEX idx_metrics_recorded ON monitoring_metrics(recorded_at)`,
		`CREATE TABLE websites(id INTEGER PRIMARY KEY, domain TEXT NOT NULL, system_user TEXT NOT NULL)`,
	} {
		if _, err := db.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	return db
}

func insertDashboardSamples(t *testing.T, db *sql.DB, samples []metricSample) {
	t.Helper()
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	stmt, err := tx.Prepare(`INSERT INTO monitoring_metrics(id,recorded_at,cpu_percent,memory_percent,load_avg_1) VALUES(?,?,?,?,?)`)
	if err != nil {
		t.Fatal(err)
	}
	defer stmt.Close()
	for _, sample := range samples {
		if _, err := stmt.Exec(sample.ID, sample.Time.UTC().Format("2006-01-02 15:04:05"), sample.CPU, sample.Mem, sample.Load); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

func TestDashboardMetricsBoundsHistoryAndPreservesActualExtrema(t *testing.T) {
	oldLocal := time.Local
	time.Local = time.UTC
	t.Cleanup(func() { time.Local = oldLocal })
	db := dashboardTestDB(t)
	now := time.Date(2026, 10, 11, 8, 0, 0, 0, time.UTC)
	samples := make([]metricSample, 15*24*60)
	byTime := make(map[string]metricSample, len(samples))
	for i := range samples {
		samples[i] = metricSample{ID: int64(i + 1), Time: now.Add(time.Duration(i-len(samples)+1) * time.Minute),
			CPU: float64((i*7)%173) / 3, Mem: 20 + float64((i*11)%139)/3, Load: float64((i*13)%101) / 25}
	}
	// Independent adjacent spikes must remain at their real timestamps, not
	// become a fabricated point with all three peaks simultaneously.
	samples[len(samples)-67].CPU = 99.7
	samples[len(samples)-66].Mem = 93.4
	samples[len(samples)-65].Load = 15.5
	for _, sample := range samples {
		byTime[sample.Time.Format(time.RFC3339)] = sample
	}
	insertDashboardSamples(t, db, samples)
	for _, r := range []string{"24h", "7d", "15d"} {
		t.Run(r, func(t *testing.T) {
			history, err := queryMetrics(context.Background(), db, r, now)
			if err != nil {
				t.Fatal(err)
			}
			duration, _ := metricRangeDuration(r)
			wantSamples := int(duration / time.Minute)
			if history.SampleCount != wantSamples || !history.Reduced || history.Displayed > dashboardMetricPointLimit || history.Displayed == 0 {
				t.Fatalf("invalid count metadata: %+v", history)
			}
			if len(history.CPU) != history.Displayed || len(history.Memory) != history.Displayed || len(history.Load) != history.Displayed || len(history.Labels) != history.Displayed || len(history.Timestamps) != history.Displayed {
				t.Fatal("unaligned arrays")
			}
			first := now.Add(-duration).Add(time.Minute).Format(time.RFC3339)
			if history.Timestamps[0] != first || history.Timestamps[len(history.Timestamps)-1] != now.Format(time.RFC3339) {
				t.Fatal("range endpoints lost")
			}
			retained := make(map[string]bool)
			for i, timestamp := range history.Timestamps {
				sample, exists := byTime[timestamp]
				if !exists || sample.CPU != history.CPU[i] || sample.Mem != history.Memory[i] || sample.Load != history.Load[i] {
					t.Fatalf("fabricated or mismatched sample at %s", timestamp)
				}
				if i > 0 && timestamp <= history.Timestamps[i-1] {
					t.Fatal("samples not chronological")
				}
				retained[timestamp] = true
			}
			// Verify every bucket's extrema for all three series, including ties.
			buckets := make(map[int64][]metricSample)
			for _, sample := range samples[len(samples)-wantSamples:] {
				bucket := int64(sample.Time.Sub(now.Add(-duration)) / (time.Duration(history.BucketSeconds) * time.Second))
				if bucket >= dashboardMetricBuckets {
					bucket = dashboardMetricBuckets - 1
				}
				buckets[bucket] = append(buckets[bucket], sample)
			}
			for _, bucket := range buckets {
				for _, value := range []func(metricSample) float64{func(s metricSample) float64 { return s.CPU }, func(s metricSample) float64 { return s.Mem }, func(s metricSample) float64 { return s.Load }} {
					min, max := value(bucket[0]), value(bucket[0])
					for _, sample := range bucket {
						if value(sample) < min {
							min = value(sample)
						}
						if value(sample) > max {
							max = value(sample)
						}
					}
					foundMin, foundMax := false, false
					for _, sample := range bucket {
						if retained[sample.Time.Format(time.RFC3339)] {
							foundMin = foundMin || value(sample) == min
							foundMax = foundMax || value(sample) == max
						}
					}
					if !foundMin || !foundMax {
						t.Fatal("bucket lost a min/max sample")
					}
				}
			}
			before := map[string]any{"labels": []string{}, "cpu": []float64{}, "memory": []float64{}, "load": []float64{}}
			for _, sample := range samples[len(samples)-wantSamples:] {
				before["labels"] = append(before["labels"].([]string), formatMetricLabel(sample.Time, r))
				before["cpu"] = append(before["cpu"].([]float64), sample.CPU)
				before["memory"] = append(before["memory"].([]float64), sample.Mem)
				before["load"] = append(before["load"].([]float64), sample.Load)
			}
			oldJSON, _ := json.Marshal(models.SuccessResponse(before))
			newJSON, _ := json.Marshal(models.SuccessResponse(history))
			t.Logf("measurement range=%s samples=%d points=%d before_json_bytes=%d after_json_bytes=%d", r, wantSamples, history.Displayed, len(oldJSON), len(newJSON))
		})
	}
}

func TestDashboardMetricLimitBoundaryAndTimeRange(t *testing.T) {
	db := dashboardTestDB(t)
	now := time.Date(2026, 10, 11, 8, 0, 0, 0, time.UTC)
	samples := make([]metricSample, dashboardMetricPointLimit)
	for i := range samples {
		samples[i] = metricSample{ID: int64(i + 1), Time: now.Add(time.Duration(i-len(samples)+1) * time.Second), CPU: float64(i % 30), Mem: 25, Load: 1}
	}
	samples = append(samples, metricSample{ID: 2000, Time: now.Add(-24 * time.Hour), CPU: 100}, metricSample{ID: 2001, Time: now.Add(time.Second), CPU: 100})
	insertDashboardSamples(t, db, samples)
	history, err := queryMetrics(context.Background(), db, "24h", now)
	if err != nil || history.Reduced || history.SampleCount != dashboardMetricPointLimit || history.Displayed != dashboardMetricPointLimit {
		t.Fatalf("limit or time boundaries changed: %+v %v", history, err)
	}
	insertDashboardSamples(t, db, []metricSample{{ID: 1201, Time: now, CPU: 99}})
	history, err = queryMetrics(context.Background(), db, "24h", now)
	if err != nil || !history.Reduced || history.SampleCount != dashboardMetricPointLimit+1 || history.Displayed > dashboardMetricPointLimit {
		t.Fatalf("first over-limit history: %+v %v", history, err)
	}
}

func TestDashboardMetricTimestampsMatchServerLocalChartLabels(t *testing.T) {
	oldLocal := time.Local
	time.Local = time.FixedZone("Asia/Shanghai", 8*60*60)
	t.Cleanup(func() { time.Local = oldLocal })
	db := dashboardTestDB(t)
	now := time.Date(2026, 10, 11, 7, 45, 0, 0, time.UTC)
	insertDashboardSamples(t, db, []metricSample{{ID: 1, Time: now, CPU: 1, Mem: 2, Load: 3}})
	history, err := queryMetrics(context.Background(), db, "24h", now)
	if err != nil || history.Labels[0] != "15:45" || history.Timestamps[0] != "2026-10-11T15:45:00+08:00" {
		t.Fatalf("chart and tooltip timezone disagree: %+v %v", history, err)
	}
}

func TestDashboardMetricsShortEmptyAndFailedHistories(t *testing.T) {
	db := dashboardTestDB(t)
	now := time.Date(2026, 10, 11, 8, 0, 0, 0, time.UTC)
	empty, err := queryMetrics(context.Background(), db, "24h", now)
	if err != nil || empty.SampleCount != 0 || empty.Labels == nil || empty.CPU == nil {
		t.Fatalf("empty history: %+v %v", empty, err)
	}
	samples := []metricSample{{ID: 1, Time: now.Add(-time.Minute), CPU: 1, Mem: 2, Load: 3}, {ID: 2, Time: now, CPU: 9, Mem: 7, Load: 5}}
	insertDashboardSamples(t, db, samples)
	history, err := queryMetrics(context.Background(), db, "24h", now)
	if err != nil || history.Reduced || history.BucketSeconds != 0 || !reflect.DeepEqual(history.CPU, []float64{1, 9}) || !reflect.DeepEqual(history.Memory, []float64{2, 7}) {
		t.Fatalf("short history changed: %+v %v", history, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := queryMetrics(ctx, db, "24h", now); err == nil {
		t.Fatal("cancelled query succeeded")
	}
	if _, err := queryMetrics(context.Background(), db, "30d", now); err == nil {
		t.Fatal("invalid range succeeded")
	}
	if _, err := queryMetrics(context.Background(), nil, "24h", now); err == nil {
		t.Fatal("missing database succeeded")
	}
	if _, err := db.Exec(`INSERT INTO monitoring_metrics(id,recorded_at) VALUES(3,?)`, now.Format("2006-01-02 15:04:05")); err != nil {
		t.Fatal(err)
	}
	if _, err := queryMetrics(context.Background(), db, "24h", now); err == nil {
		t.Fatal("corrupt sample became a successful partial history")
	}
}

func TestDashboardMetricsDenseTiesRemainBoundedAndRetainEndpoints(t *testing.T) {
	db := dashboardTestDB(t)
	now := time.Date(2026, 10, 11, 8, 0, 0, 0, time.UTC)
	samples := make([]metricSample, 2000)
	for i := range samples {
		samples[i] = metricSample{ID: int64(i + 1), Time: now.Add(-time.Minute), CPU: 1, Mem: 2, Load: 3}
	}
	samples[1000].CPU = 100
	samples[1001].Mem = 99
	samples[1002].Load = 25
	insertDashboardSamples(t, db, samples)
	history, err := queryMetrics(context.Background(), db, "24h", now)
	if err != nil {
		t.Fatal(err)
	}
	if !history.Reduced || history.Displayed > 8 || history.CPU[0] != 1 || history.CPU[len(history.CPU)-1] != 1 {
		t.Fatalf("dense ties: %+v", history)
	}
	for _, test := range []struct {
		values []float64
		peak   float64
	}{{history.CPU, 100}, {history.Memory, 99}, {history.Load, 25}} {
		found := false
		for _, v := range test.values {
			found = found || v == test.peak
		}
		if !found {
			t.Fatal("lost a dense bucket peak")
		}
	}
}
