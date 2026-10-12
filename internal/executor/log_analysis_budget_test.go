package executor

import (
	"compress/gzip"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zangwp/OLS-WPanel/internal/models"
)

func TestLogAnalysisSlotWaitCanBeCancelled(t *testing.T) {
	ctx1, done1, err := acquireLogAnalysisScan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer done1()
	_, done2, err := acquireLogAnalysisScan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer done2()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if _, _, err := acquireLogAnalysisScan(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("wait=%v", err)
	}
	if ctx1.Err() != nil {
		t.Fatal("cancelled another subscriber")
	}
}

func TestLogAnalysisDoesNotReportCorruptOrOversizedLogAsSuccess(t *testing.T) {
	for _, item := range []struct{ name, body string }{
		{"access.log.1.gz", "not gzip"},
		{"access.log", strings.Repeat("x", 1024*1024+1)},
	} {
		t.Run(item.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, item.name), []byte(item.body), 0600); err != nil {
				t.Fatal(err)
			}
			site := &models.Website{ID: 1, LogDir: dir}
			now := time.Now()
			if report, err := AnalyzeWebsiteLogs(site, now.Add(-time.Hour), now, nil, "en-US"); err == nil || report != nil {
				t.Fatalf("summary=%+v err=%v", report, err)
			}
			if detail, err := AnalyzeWebsiteLogDetails(site, now.Add(-time.Hour), now, nil, "status", "404", 1, 20); err == nil || detail != nil {
				t.Fatalf("detail=%+v err=%v", detail, err)
			}
		})
	}
}

func TestLogAnalysisCancelledScanReleasesSlot(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	dir := t.TempDir()
	path := filepath.Join(dir, "access.log")
	if err := os.WriteFile(path, []byte("first\nsecond\n"), 0600); err != nil {
		t.Fatal(err)
	}
	count := 0
	err := scanLogAnalysisDetailFileContext(ctx, path, func(string) bool { count++; cancel(); return true })
	if count != 1 || !errors.Is(err, context.Canceled) {
		t.Fatalf("count=%d err=%v", count, err)
	}
	if report, err := AnalyzeWebsiteLogsContext(ctx, &models.Website{ID: 1, LogDir: dir}, time.Now().Add(-time.Hour), time.Now(), nil, "en-US"); report != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("report=%+v err=%v", report, err)
	}
	if len(logAnalysisScanSlots) != 0 {
		t.Fatal("cancelled scan leaked a slot")
	}
}

func TestLogAnalysisDetailFlagsByteLimitInsteadOfClaimingComplete(t *testing.T) {
	dir := t.TempDir()
	f, err := os.Create(filepath.Join(dir, "access.log.1.gz"))
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(f)
	line := strings.Repeat("x", 16383) + "\n"
	for bytes := int64(0); bytes <= logAnalysisDetailMaxBytes; bytes += int64(len(line)) {
		if _, err := gz.Write([]byte(line)); err != nil {
			t.Fatal(err)
		}
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	detail, err := AnalyzeWebsiteLogDetails(&models.Website{ID: 1, LogDir: dir}, now.Add(-time.Hour), now, nil, "status", "404", 1, 20)
	if err != nil || !detail.Truncated || detail.BytesScanned <= logAnalysisDetailMaxBytes {
		t.Fatalf("detail=%+v err=%v", detail, err)
	}
}
