package executor

import (
	"testing"
	"time"
	_ "time/tzdata"
)

func TestDailyBackupScheduleKeepsCalendarHourAcrossDST(t *testing.T) {
	zone, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Fatal(err)
	}
	for _, date := range []struct {
		month  time.Month
		day    int
		offset int
	}{{time.March, 7, -4 * 3600}, {time.October, 31, -5 * 3600}} {
		now := time.Date(2026, date.month, date.day, 5, 0, 0, 0, zone)
		next := nextDailyBackupTime(now, 4, 0)
		_, offset := next.Zone()
		want := time.Date(now.Year(), now.Month(), now.Day()+1, 4, 0, 0, 0, zone)
		if !next.Equal(want) || next.Hour() != 4 || next.Minute() != 0 || offset != date.offset {
			t.Fatalf("local 04:00 drifted across DST: now=%s next=%s", now, next)
		}
	}
	for _, now := range []time.Time{time.Date(2026, 12, 31, 5, 0, 0, 0, time.UTC), time.Date(2026, 2, 28, 5, 0, 0, 0, time.UTC)} {
		next := nextDailyBackupTime(now, 4, 0)
		if !next.After(now) || next.Hour() != 4 || next.Day() != 1 {
			t.Fatalf("calendar boundary failed: %s => %s", now, next)
		}
	}
	now := time.Date(2026, 10, 15, 1, 0, 0, 0, time.UTC)
	if next := nextDailyBackupTime(now, 2, 30); next.Day() != now.Day() || next.Hour() != 2 || next.Minute() != 30 {
		t.Fatal("future slot was skipped", next)
	}
}
