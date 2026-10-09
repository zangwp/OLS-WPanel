package executor

import (
	"bufio"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/zangwp/OLS-WPanel/internal/database"
)

// Persist only classified security events. Each producer has its own cursor;
// the legacy wp-security.log cursor remains compatible with existing installs.

const wpSecurityEventRetentionDays = 90

const (
	wpSecurityMaxLineBytes  = 64 * 1024
	wpSecurityMaxBatchBytes = 2 * 1024 * 1024
	wpSecurityMaxBatchLines = 5000
)

var wpSecurityIngestCycleMu sync.Mutex

// IngestWPSecurityEvents 对所有 WordPress 站点做一次增量日志摄取，返回新入库的事件数。
func IngestWPSecurityEvents() (int, error) {
	wpSecurityIngestCycleMu.Lock()
	defer wpSecurityIngestCycleMu.Unlock()
	db := database.GetDB()
	if db == nil {
		return 0, fmt.Errorf("database is nil")
	}

	sites, err := listWordPressSecuritySites(db)
	if err != nil {
		return 0, err
	}

	checker := newSearchBotIPChecker(db)
	total := 0
	for _, site := range sites {
		n, err := ingestSiteSecurityEvents(db, site, checker)
		total += n
		if err != nil {
			log.Printf("wp security event ingest skipped for %s: %v", site.Domain, err)
			continue
		}
	}
	return total, nil
}

func ingestSiteSecurityEvents(db *sql.DB, site wpSecuritySite, checker *searchBotIPChecker) (int, error) {
	if !wpSecurityLogDirAllowed(site.LogDir) {
		return 0, nil
	}

	total := 0
	var firstErr error
	for _, source := range []string{wpSecurityLegacyLog, wpSecurityAccessLog, wpSecurityLoginLog} {
		count, err := ingestSiteSecuritySource(db, site, source, checker)
		total += count
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return total, firstErr
}

// A source commits its events and complete-line cursor in one transaction.
// Failed inserts retain the failed line for retry; failed cursor writes roll
// back the events, avoiding duplicates on the next cycle.
func ingestSiteSecuritySource(db *sql.DB, site wpSecuritySite, source string, checker *searchBotIPChecker) (int, error) {
	path := filepath.Join(site.LogDir, source)
	f, err := openSafeWPSecurityLog(path, wpSecurityLogDirAllowed)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return 0, err
	}

	tx, err := db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	storedPosition, err := getWPSecuritySourceLogPosition(tx, site.ID, source)
	if err != nil {
		return 0, err
	}
	offset := storedPosition.byteOffset
	firstLineHash := firstCompleteLineHash(f)
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return 0, err
	}
	if offset < 0 || info.Size() < offset || (storedPosition.firstLineHash != "" && firstLineHash != "" && storedPosition.firstLineHash != firstLineHash) {
		// 文件比记录的偏移还小，说明已被 copytruncate 轮转，从头重新读取新内容。
		// 高流量站点轮转后文件可能很快增长到超过旧偏移，首行指纹可覆盖这个场景。
		offset = 0
	}
	if offset > 0 {
		if _, err := f.Seek(offset, io.SeekStart); err != nil {
			return 0, err
		}
	}

	reader := bufio.NewReaderSize(io.LimitReader(f, wpSecurityMaxBatchBytes), wpSecurityMaxLineBytes)
	var consumed int64
	count := 0
	var ingestErr error
	for lines := 0; lines < wpSecurityMaxBatchLines; lines++ {
		lineBytes, byteCount, oversized, readErr := readBoundedWPSecurityLine(reader)
		if readErr == nil {
			// 只有以换行符结尾的完整行才计入已消费字节；
			// 末尾还没写完的半行留到下一轮再读，避免把偏移记到半行中间。
			if oversized {
				consumed += byteCount
				continue
			}
			line := strings.TrimRight(string(lineBytes), "\r\n")
			inserted, err := ingestSecuritySourceLogLine(tx, site, line, source, checker)
			if err != nil {
				ingestErr = err
				break
			}
			consumed += byteCount
			if inserted {
				count++
			}
		}
		if readErr != nil {
			if readErr != io.EOF {
				ingestErr = readErr
			}
			break
		}
	}

	newOffset := offset + consumed
	if err := setWPSecuritySourceLogPosition(tx, site.ID, source, newOffset, firstLineHash); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return count, ingestErr
}

func ingestSecurityLogLine(db *sql.DB, site wpSecuritySite, line string, checker *searchBotIPChecker) (bool, error) {
	return ingestSecuritySourceLogLine(db, site, line, wpSecurityLegacyLog, checker)
}

type wpSecuritySQLStore interface {
	Exec(string, ...any) (sql.Result, error)
	QueryRow(string, ...any) *sql.Row
}

func ingestSecuritySourceLogLine(db wpSecuritySQLStore, site wpSecuritySite, line, source string, checker *searchBotIPChecker) (bool, error) {
	evidence, ok := parseWPSecurityLogEvidence(line, source, checker)
	if !ok || evidence.eventType == "" {
		return false, nil
	}

	_, err := db.Exec(`INSERT INTO wp_security_events
		(site_id, domain, ip_address, event_type, risk_level, method, path, user_agent, status, message, occurred_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		site.ID, site.Domain, evidence.ip, evidence.eventType, evidence.risk, evidence.method,
		truncateRunes(evidence.uri, 512), truncateRunes(evidence.userAgent, 256), evidence.status, evidence.message,
		evidence.occurred.UTC().Format("2006-01-02 15:04:05"),
	)
	if err != nil {
		log.Printf("wp security event insert failed for %s: %v", site.Domain, err)
		return false, err
	}
	return true, nil
}

type wpSecurityLogPosition struct {
	byteOffset    int64
	firstLineHash string
}

func getWPSecurityLogPosition(db *sql.DB, siteID int) wpSecurityLogPosition {
	pos, _ := getWPSecuritySourceLogPosition(db, siteID, wpSecurityLegacyLog)
	return pos
}

func setWPSecurityLogPosition(db *sql.DB, siteID int, offset int64, firstLineHash string) error {
	return setWPSecuritySourceLogPosition(db, siteID, wpSecurityLegacyLog, offset, firstLineHash)
}

func getWPSecuritySourceLogPosition(db wpSecuritySQLStore, siteID int, source string) (wpSecurityLogPosition, error) {
	var pos wpSecurityLogPosition
	var err error
	if source == wpSecurityLegacyLog {
		err = db.QueryRow(`SELECT byte_offset, first_line_hash FROM wp_security_log_positions WHERE site_id = ?`, siteID).Scan(&pos.byteOffset, &pos.firstLineHash)
	} else {
		err = db.QueryRow(`SELECT byte_offset, first_line_hash FROM wp_security_log_source_positions WHERE site_id = ? AND source = ?`, siteID, source).Scan(&pos.byteOffset, &pos.firstLineHash)
	}
	if err == sql.ErrNoRows {
		err = nil
	}
	return pos, err
}

func setWPSecuritySourceLogPosition(db wpSecuritySQLStore, siteID int, source string, offset int64, firstLineHash string) error {
	if source == wpSecurityLegacyLog {
		_, err := db.Exec(`INSERT INTO wp_security_log_positions (site_id, byte_offset, first_line_hash, updated_at)
		VALUES (?, ?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(site_id) DO UPDATE SET byte_offset = excluded.byte_offset, first_line_hash = excluded.first_line_hash, updated_at = excluded.updated_at`,
			siteID, offset, firstLineHash)
		return err
	}
	_, err := db.Exec(`INSERT INTO wp_security_log_source_positions (site_id, source, byte_offset, first_line_hash, updated_at)
		VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(site_id,source) DO UPDATE SET byte_offset = excluded.byte_offset, first_line_hash = excluded.first_line_hash, updated_at = excluded.updated_at`,
		siteID, source, offset, firstLineHash)
	return err
}

// ReadSlice keeps memory bounded even for an oversized malicious log row. Only
// a complete newline-terminated row can advance the cursor. A batch boundary or
// unfinished trailing row is retried on the next cycle.
func readBoundedWPSecurityLine(reader *bufio.Reader) ([]byte, int64, bool, error) {
	var line []byte
	var bytes int64
	oversized := false
	for {
		fragment, err := reader.ReadSlice('\n')
		bytes += int64(len(fragment))
		if !oversized && bytes <= wpSecurityMaxLineBytes {
			line = append(line, fragment...)
		} else {
			line, oversized = nil, true
		}
		if err == bufio.ErrBufferFull {
			continue
		}
		return line, bytes, oversized, err
	}
}

func firstCompleteLineHash(f *os.File) string {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return ""
	}
	reader := bufio.NewReaderSize(io.LimitReader(f, wpSecurityMaxLineBytes), wpSecurityMaxLineBytes)
	lineBytes, _, oversized, err := readBoundedWPSecurityLine(reader)
	if err != nil || oversized {
		return ""
	}
	line := strings.TrimRight(string(lineBytes), "\r\n")
	sum := sha256.Sum256([]byte(line))
	return hex.EncodeToString(sum[:])
}

// CountRecentSecurityEventsByIP 统计指定事件类型在时间窗口内每个 IP 的出现次数，
// 供方案 D 阶段四的告警规则使用。
func CountRecentSecurityEventsByIP(eventType string, since time.Time) (map[string]int, error) {
	db := database.GetDB()
	if db == nil {
		return nil, fmt.Errorf("database is nil")
	}

	rows, err := db.Query(`SELECT ip_address, COUNT(*) FROM wp_security_events
		WHERE event_type = ? AND occurred_at >= ?
		GROUP BY ip_address`,
		eventType, since.UTC().Format("2006-01-02 15:04:05"))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	counts := map[string]int{}
	for rows.Next() {
		var ip string
		var count int
		if err := rows.Scan(&ip, &count); err != nil {
			continue
		}
		counts[ip] = count
	}
	return counts, rows.Err()
}

// WPSecurityAlertOffender 是超过告警阈值的单个 IP 摘要，供邮件/Webhook 告警使用。
type WPSecurityAlertOffender struct {
	IP    string
	Count int
	Paths []string
}

// topWPSecurityOffenders 返回时间窗口内命中次数达到阈值的 IP 列表（按次数降序），
// 每个 IP 附带命中次数最多的若干条请求路径样本。
func topWPSecurityOffenders(eventType string, since time.Time, threshold, pathLimit int) ([]WPSecurityAlertOffender, error) {
	db := database.GetDB()
	if db == nil {
		return nil, fmt.Errorf("database is nil")
	}

	counts, err := CountRecentSecurityEventsByIP(eventType, since)
	if err != nil {
		return nil, err
	}

	var offenders []WPSecurityAlertOffender
	for ip, count := range counts {
		if count < threshold {
			continue
		}
		paths, err := topWPSecurityEventPaths(db, eventType, since, ip, pathLimit)
		if err != nil {
			paths = nil
		}
		offenders = append(offenders, WPSecurityAlertOffender{IP: ip, Count: count, Paths: paths})
	}
	sort.Slice(offenders, func(i, j int) bool {
		if offenders[i].Count != offenders[j].Count {
			return offenders[i].Count > offenders[j].Count
		}
		return offenders[i].IP < offenders[j].IP
	})
	return offenders, nil
}

func topWPSecurityEventPaths(db *sql.DB, eventType string, since time.Time, ip string, limit int) ([]string, error) {
	rows, err := db.Query(`SELECT path, COUNT(*) c FROM wp_security_events
		WHERE event_type = ? AND ip_address = ? AND occurred_at >= ?
		GROUP BY path ORDER BY c DESC, path ASC LIMIT ?`,
		eventType, ip, since.UTC().Format("2006-01-02 15:04:05"), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var paths []string
	for rows.Next() {
		var path string
		var count int
		if err := rows.Scan(&path, &count); err != nil {
			continue
		}
		paths = append(paths, fmt.Sprintf("%s × %d", path, count))
	}
	return paths, rows.Err()
}

// PruneWPSecurityEvents 删除超过保留期限的历史事件，避免表无限增长。
func PruneWPSecurityEvents(retentionDays int) error {
	db := database.GetDB()
	if db == nil {
		return fmt.Errorf("database is nil")
	}
	if retentionDays <= 0 {
		retentionDays = wpSecurityEventRetentionDays
	}
	cutoff := time.Now().UTC().Add(-time.Duration(retentionDays) * 24 * time.Hour).Format("2006-01-02 15:04:05")
	_, err := db.Exec(`DELETE FROM wp_security_events WHERE occurred_at < ?`, cutoff)
	return err
}

// StartWPSecurityEventIngestor 启动后台增量摄取调度：每 wpSecurityIngestorInterval
// 读取一次新增日志，并顺带清理过期历史事件。StopWPSecurityEventIngestor 可关闭
// 该调度，供 main.go 在收到 SIGINT/SIGTERM 时调用（审核优化项 3.2）。
//
// 保留初始 runWPSecurityEventIngestCycle() 调用（select 之前），保证面板启动后
// 立即摄取一次，而不是等到第一个 tick。代价是 Stop 无法中断正在执行的初始摄取，
// 但该调用在生产环境秒级完成，可接受。
var (
	wpSecurityIngestorMu       sync.Mutex
	wpSecurityIngestorStopCh   chan struct{}
	wpSecurityIngestorDone     chan struct{}
	wpSecurityIngestorInterval = 5 * time.Minute // var 而非 const，便于测试覆盖
)

func StartWPSecurityEventIngestor() {
	wpSecurityIngestorMu.Lock()
	wpSecurityIngestorStopCh = make(chan struct{})
	wpSecurityIngestorDone = make(chan struct{})
	stopCh := wpSecurityIngestorStopCh
	done := wpSecurityIngestorDone
	wpSecurityIngestorMu.Unlock()

	go func() {
		defer close(done)
		runWPSecurityEventIngestCycle()
		ticker := time.NewTicker(wpSecurityIngestorInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				runWPSecurityEventIngestCycle()
			case <-stopCh:
				return
			}
		}
	}()
}

// StopWPSecurityEventIngestor 关闭后台摄取调度。幂等：多次调用安全。
// 调用后 wpSecurityIngestorDone 会被关闭，调用方可 select 等待退出完成。
func StopWPSecurityEventIngestor() {
	wpSecurityIngestorMu.Lock()
	defer wpSecurityIngestorMu.Unlock()
	if wpSecurityIngestorStopCh != nil {
		close(wpSecurityIngestorStopCh)
		wpSecurityIngestorStopCh = nil
	}
}

func runWPSecurityEventIngestCycle() {
	if _, err := IngestWPSecurityEvents(); err != nil {
		log.Printf("wp security event ingest failed: %v", err)
	}
	if err := PruneWPSecurityEvents(wpSecurityEventRetentionDays); err != nil {
		log.Printf("wp security event prune failed: %v", err)
	}
}

func truncateRunes(s string, maxRunes int) string {
	runes := []rune(s)
	if len(runes) <= maxRunes {
		return s
	}
	return string(runes[:maxRunes])
}
