package executor

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/zangwp/OLS-WPanel/internal/database"
)

const oomJournalLookback = 2 * time.Minute
const oomJournalByteLimit = 2 * 1024 * 1024
const oomJournalLineLimit = 64 * 1024
const oomJournalEventLimit = 512

var oomKilledProcessPattern = regexp.MustCompile(`^([0-9]+(?:\.[0-9]+)?)\s+.*Out of memory: Killed process ([0-9]+) \(([^)]+)\)`)

type oomEvent struct {
	Key        string
	Process    string
	PID        int
	OccurredAt time.Time
}

// StartOOMMonitor records kernel OOM kills independently from resource threshold alerts.
func StartOOMMonitor() {
	go func() {
		checkOOMEvents()
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			checkOOMEvents()
		}
	}()
}

func checkOOMEvents() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	since := fmt.Sprintf("%d seconds ago", int(oomJournalLookback.Seconds()))
	events, incomplete, err := readOOMJournalCommand(ctx, "journalctl", "-k", "--since", since, "--no-pager", "-o", "short-unix", "--reverse")
	if err != nil {
		log.Printf("[OOM监控] 本次内核日志检查未完成，不能据此判定没有 OOM，后续周期将继续检查: %v", err)
	} else if incomplete {
		log.Printf("[OOM监控] 本次内核日志检查达到字节、行或事件预算，仅记录已读取事件；检查不完整，后续周期将继续检查")
	}
	for _, event := range events {
		if err := recordOOMEvent(event); err != nil {
			log.Printf("[OOM监控] 记录事件失败: %v", err)
		}
	}
}

// readOOMJournalCommand always waits for its child. Budget exhaustion cancels
// it immediately; timeout/cancellation cannot leave journalctl running behind.
func readOOMJournalCommand(ctx context.Context, name string, args ...string) ([]oomEvent, bool, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.WaitDelay = time.Second
	cmd.Stderr = io.Discard
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, true, err
	}
	if err := cmd.Start(); err != nil {
		stdout.Close()
		return nil, true, err
	}
	events, incomplete, scanErr := scanOOMJournal(stdout)
	if incomplete || scanErr != nil {
		cancel()
	}
	_ = stdout.Close()
	waitErr := cmd.Wait()
	if scanErr != nil {
		return events, true, scanErr
	}
	if incomplete {
		return events, true, nil
	}
	if waitErr != nil {
		return events, true, waitErr
	}
	return events, false, nil
}

func scanOOMJournal(reader io.Reader) ([]oomEvent, bool, error) {
	limited := &io.LimitedReader{R: reader, N: oomJournalByteLimit + 1}
	scanner := bufio.NewScanner(limited)
	scanner.Buffer(make([]byte, 4096), oomJournalLineLimit)
	events := make([]oomEvent, 0)
	for scanner.Scan() {
		events = append(events, parseOOMEvents(scanner.Text())...)
		if len(events) >= oomJournalEventLimit {
			return events, true, nil
		}
	}
	if err := scanner.Err(); err != nil {
		if errors.Is(err, bufio.ErrTooLong) {
			return events, true, nil
		}
		return events, true, err
	}
	return events, limited.N == 0, nil
}

func parseOOMEvents(output string) []oomEvent {
	var events []oomEvent
	for _, line := range strings.Split(output, "\n") {
		match := oomKilledProcessPattern.FindStringSubmatch(line)
		if len(match) != 4 {
			continue
		}
		unixSeconds, err := strconv.ParseFloat(match[1], 64)
		if err != nil {
			continue
		}
		pid, err := strconv.Atoi(match[2])
		if err != nil {
			continue
		}
		occurredAt := time.Unix(0, int64(unixSeconds*float64(time.Second))).UTC()
		events = append(events, oomEvent{
			Key:        fmt.Sprintf("%s:%d:%s", match[1], pid, match[3]),
			Process:    match[3],
			PID:        pid,
			OccurredAt: occurredAt,
		})
	}
	return events
}

func recordOOMEvent(event oomEvent) error {
	process := oomProcessLabel(event.Process)
	message := fmt.Sprintf(
		"系统内存耗尽，内核强制终止 %s（PID %d），发生于 %s；服务可能已由 systemd 自动重启",
		process, event.PID, event.OccurredAt.Local().Format("2006-01-02 15:04:05"),
	)
	result, err := database.GetDB().Exec(
		`INSERT OR IGNORE INTO system_oom_events
		 (event_key, process, pid, message, occurred_at) VALUES (?, ?, ?, ?, ?)`,
		event.Key, event.Process, event.PID, message, event.OccurredAt,
	)
	if err != nil {
		return err
	}
	inserted, err := result.RowsAffected()
	if err != nil || inserted == 0 || !isRuleEnabled("alert_oom") {
		return err
	}

	if snapshot := captureIncidentResourceSnapshot(); snapshot != "" {
		message += "；" + snapshot
		if _, err := database.GetDB().Exec(
			"UPDATE system_oom_events SET message = ? WHERE event_key = ?",
			message, event.Key,
		); err != nil {
			return err
		}
	}
	sendResolvedAlertEvent("alert_oom", "系统内存耗尽", message, "请检查当时的内存占用和相关服务日志。")
	return nil
}

func oomProcessLabel(process string) string {
	switch {
	case process == "mariadbd" || process == "mysqld":
		return "MariaDB"
	case strings.HasPrefix(process, "lsphp"):
		return "LSPHP"
	case process == "redis-server":
		return "Redis"
	case process == "lshttpd" || process == "openlitespeed":
		return "OpenLiteSpeed"
	case process == "ols-wpanel":
		return "OLS WPanel"
	default:
		return process
	}
}
