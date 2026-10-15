package executor

import "time"

// Advance the calendar day rather than elapsed hours, which differ at DST
// transitions. For a nonexistent/ambiguous local slot time.Date supplies the
// timezone's valid adjacent instant; a passed instant advances to the next day.
func nextDailyBackupTime(now time.Time, hour, minute int) time.Time {
	next := time.Date(now.Year(), now.Month(), now.Day(), hour, minute, 0, 0, now.Location())
	if now.After(next) {
		next = time.Date(now.Year(), now.Month(), now.Day()+1, hour, minute, 0, 0, now.Location())
	}
	return next
}
