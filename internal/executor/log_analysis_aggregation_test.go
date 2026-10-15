package executor

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zangwp/OLS-WPanel/internal/models"
)

func writeAggregationLog(t *testing.T, dir, name string, rows, first, pathLength int, repeated bool, modified time.Time) {
	t.Helper()
	f, err := os.Create(filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	w := bufio.NewWriter(f)
	padding := strings.Repeat("p", pathLength)
	for i := 0; i < rows; i++ {
		n := first + i
		if repeated {
			n = 0
		}
		if _, err := fmt.Fprintf(w, "198.51.100.10 - - [15/Oct/2026:12:00:00 +0000] \"GET /%s%d HTTP/1.1\" 200 12 \"-\" \"Mozilla/5.0\"\n", padding, n); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(f.Name(), modified, modified); err != nil {
		t.Fatal(err)
	}
}

func TestLogAnalysisAggregationBudgetStopsAcrossRotatedFiles(t *testing.T) {
	start := time.Date(2026, 10, 15, 11, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name                 string
		rows, files, pathLen int
	}{
		{"distinct keys", 60000, 3, 0},
		{"retained key bytes", 1500, 4, 4096},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			for i := 0; i < tc.files; i++ {
				writeAggregationLog(t, dir, fmt.Sprintf("access.log.%d", i), tc.rows, i*tc.rows, tc.pathLen, false, start.Add(-time.Duration(i)*time.Hour))
			}
			site := &models.Website{ID: 1, LogDir: dir}
			report, err := AnalyzeWebsiteLogs(site, start, start.Add(2*time.Hour), nil, "en-US")
			if err != nil {
				t.Fatal(err)
			}
			if !report.Truncated || report.AccessRequests <= tc.rows || report.AccessRequests >= tc.rows*tc.files || report.FilesScanned >= tc.files || report.BytesScanned >= logAnalysisMaxBytes {
				t.Fatalf("summary did not stop on the shared aggregation budget: %+v", report)
			}
			if len(report.StatusCodes) != 1 || report.StatusCodes[0].Count != report.AccessRequests || report.LinesInRange != report.AccessRequests || report.UniqueIPs != 1 {
				t.Fatalf("summary partially counted a rejected row: %+v", report)
			}
			detail, err := AnalyzeWebsiteLogDetails(site, start, start.Add(2*time.Hour), nil, "status", "200", 1, 20)
			if err != nil {
				t.Fatal(err)
			}
			if !detail.Truncated || detail.Total == 0 || detail.Total >= report.AccessRequests || detail.BytesScanned >= logAnalysisDetailMaxBytes || len(detail.Lines) != 20 {
				t.Fatalf("detail did not stop on the aggregation budget: %+v", detail)
			}
			if len(detail.StatusCodes) != 1 || detail.StatusCodes[0].Count != detail.Total || detail.UniquePaths != detail.Total || detail.UniqueIPs != 1 {
				t.Fatalf("detail partially counted a rejected row: %+v", detail)
			}
		})
	}
}

func TestLogAnalysisAggregationBudgetAllowsRepeatedTraffic(t *testing.T) {
	dir := t.TempDir()
	start := time.Date(2026, 10, 15, 11, 0, 0, 0, time.UTC)
	rows := logAnalysisMaxAggregationKeys + 1
	writeAggregationLog(t, dir, "access.log", rows, 0, 0, true, start)
	site := &models.Website{ID: 1, LogDir: dir}
	report, err := AnalyzeWebsiteLogs(site, start, start.Add(2*time.Hour), nil, "en-US")
	if err != nil || report.Truncated || report.AccessRequests != rows || len(report.TopPaths) != 1 || report.TopPaths[0].Count != rows {
		t.Fatalf("ordinary repeated traffic was truncated: report=%+v err=%v", report, err)
	}
	detail, err := AnalyzeWebsiteLogDetails(site, start, start.Add(2*time.Hour), nil, "status", "200", 2, 20)
	if err != nil || detail.Truncated || detail.Total != rows || len(detail.Lines) != 20 || detail.UniquePaths != 1 {
		t.Fatalf("ordinary detail traffic was truncated: detail=%+v err=%v", detail, err)
	}
}

func TestLogAnalysisAggregationBudgetIncludesBotDeduplication(t *testing.T) {
	dir := t.TempDir()
	f, err := os.Create(filepath.Join(dir, "wp-security.log"))
	if err != nil {
		t.Fatal(err)
	}
	w := bufio.NewWriter(f)
	ua := "Googlebot " + strings.Repeat("x", 8192)
	for i := 0; i < 2200; i++ {
		if _, err := fmt.Fprintf(w, "198.51.100.10 - - [15/Oct/2026:12:00:00 +0000] \"GET /bot-%d HTTP/1.1\" 403 12 \"-\" \"%s\"\n", i, ua); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	start := time.Date(2026, 10, 15, 11, 0, 0, 0, time.UTC)
	site := &models.Website{ID: 1, LogDir: dir}
	report, err := AnalyzeWebsiteLogs(site, start, start.Add(2*time.Hour), nil, "en-US")
	if err != nil {
		t.Fatal(err)
	}
	if !report.Truncated || report.AccessRequests != 0 || report.SecurityRequestCount == 0 || report.SecurityRequestCount >= 2200 || len(report.Bots) != 1 || report.Bots[0].Count != report.SecurityRequestCount {
		t.Fatalf("summary bot deduplication bypassed byte budget: %+v", report)
	}
	detail, err := AnalyzeWebsiteLogDetails(site, start, start.Add(2*time.Hour), nil, "bot", "Googlebot:unknown", 1, 20)
	if err != nil || !detail.Truncated || detail.Total == 0 || detail.Total >= 2200 || len(detail.Lines) != 20 {
		t.Fatalf("detail bot deduplication bypassed byte budget: detail=%+v err=%v", detail, err)
	}
}

func TestLogAnalysisTopResultsReleaseUnreturnedEntries(t *testing.T) {
	values := make(map[string]int)
	for i := 0; i < 5000; i++ {
		values[fmt.Sprintf("/path-%04d", i)] = 5000 - i
	}
	result := sortedCounts(values, logAnalysisTopLimit)
	if len(result) != logAnalysisTopLimit || cap(result) > 2*logAnalysisTopLimit || result[0].Name != "/path-0000" || result[0].Count != 5000 {
		t.Fatalf("top results retained the full sort array or changed ordering: len=%d cap=%d first=%+v", len(result), cap(result), result[0])
	}
}

func TestLogAnalysisAggregationBudgetRejectsWholeRecord(t *testing.T) {
	budget := logAggregationBudget{keys: logAnalysisMaxAggregationKeys - 1, keyBytes: 10}
	if budget.reserve([]string{"first", "second"}) || budget.keys != logAnalysisMaxAggregationKeys-1 || budget.keyBytes != 10 {
		t.Fatalf("rejected record partially consumed the key budget: %+v", budget)
	}
	budget = logAggregationBudget{keyBytes: logAnalysisMaxAggregationKeyBytes - 2}
	if budget.reserve([]string{"one", "two"}) || budget.keys != 0 || budget.keyBytes != logAnalysisMaxAggregationKeyBytes-2 {
		t.Fatalf("rejected record partially consumed the byte budget: %+v", budget)
	}
}

func TestLogAnalysisPartialReportDoesNotClaimCompleteToAI(t *testing.T) {
	_, prompt, err := BuildLogAnalysisPrompt(&models.LogAnalysisReport{Truncated: true})
	if err != nil || !strings.Contains(prompt, `"truncated":true`) || strings.Contains(prompt, "完整扫描指定时间段") || !strings.Contains(prompt, "只覆盖部分日志") {
		t.Fatalf("partial report presented as complete: prompt=%q err=%v", prompt, err)
	}
}
