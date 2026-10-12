package executor

import (
	"bufio"
	"compress/gzip"
	"context"
	"database/sql"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/zangwp/OLS-WPanel/internal/models"
)

const logAnalysisDetailMaxPageSize = 100

// AnalyzeWebsiteLogDetails rescans access logs for one drill-down dimension.
func AnalyzeWebsiteLogDetails(site *models.Website, startAt, endAt time.Time, db *sql.DB, kind, value string, page, pageSize int) (*models.LogAnalysisDetail, error) {
	return AnalyzeWebsiteLogDetailsContext(context.Background(), site, startAt, endAt, db, kind, value, page, pageSize)
}

// ValidateLogAnalysisDetailSelection validates the dimension without rereading
// website logs (for example when creating a diagnostic conversation).
func ValidateLogAnalysisDetailSelection(kind, value string) error {
	if kind != "status" && kind != "path" && kind != "bot" && kind != "ip" && kind != "category" {
		return fmt.Errorf("invalid detail kind")
	}
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 500 {
		return fmt.Errorf("invalid detail value")
	}
	if kind == "status" {
		code, err := strconv.Atoi(value)
		if err != nil || len(value) != 3 || code < 100 || code > 599 {
			return fmt.Errorf("invalid status code")
		}
	}
	if kind == "ip" && net.ParseIP(value) == nil {
		return fmt.Errorf("invalid IP address")
	}
	if kind == "category" && !validLogTrafficCategory(value) {
		return fmt.Errorf("invalid traffic category")
	}
	return nil
}

func AnalyzeWebsiteLogDetailsContext(ctx context.Context, site *models.Website, startAt, endAt time.Time, db *sql.DB, kind, value string, page, pageSize int) (*models.LogAnalysisDetail, error) {
	if site == nil || site.ID <= 0 || !startAt.Before(endAt) || endAt.Sub(startAt) > 7*24*time.Hour {
		return nil, fmt.Errorf("invalid log analysis detail request")
	}
	value = strings.TrimSpace(value)
	if err := ValidateLogAnalysisDetailSelection(kind, value); err != nil {
		return nil, err
	}
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > logAnalysisDetailMaxPageSize {
		pageSize = 20
	}
	ctx, release, err := acquireLogAnalysisScan(ctx)
	if err != nil {
		return nil, err
	}
	defer release()

	cleanDir := filepath.Clean(site.LogDir)
	if !filepath.IsAbs(cleanDir) {
		return nil, fmt.Errorf("invalid site log directory")
	}
	entries, err := os.ReadDir(cleanDir)
	if err != nil {
		return nil, fmt.Errorf("read site log directory: %w", err)
	}
	var files []string
	for _, entry := range entries {
		if entry.IsDir() || (!strings.HasPrefix(entry.Name(), "access.log") && !strings.HasPrefix(entry.Name(), "wp-security.log")) || !isAnalyzableLogName(entry.Name()) {
			continue
		}
		path := filepath.Join(cleanDir, entry.Name())
		resolved, resolveErr := filepath.EvalSymlinks(path)
		if resolveErr == nil && isPathWithinRoot(cleanDir, resolved) {
			files = append(files, resolved)
		}
	}
	sortLogFilesNewestFirst(files)

	result := &models.LogAnalysisDetail{Kind: kind, Value: value, Page: page, PageSize: pageSize, Lines: []string{}, SecurityEventRetentionDays: wpSecurityEventRetentionDays, BanHistoryLimit: 300}
	ips := map[string]int{}
	paths := map[string]int{}
	statuses := map[string]int{}
	userAgents := map[string]int{}
	methods := map[string]int{}
	hourly := map[string]int{}
	ipPathPairs := map[string]int{}
	offset := (page - 1) * pageSize
	checker := newSearchBotIPChecker(db)
	seenBots := map[string]struct{}{}
	var bytesScanned int64
	for _, path := range files {
		if bytesScanned >= logAnalysisDetailMaxBytes {
			result.Truncated = true
			break
		}
		err := scanLogAnalysisDetailFileContext(ctx, path, func(line string) bool {
			bytesScanned += int64(len(line) + 1)
			if bytesScanned > logAnalysisDetailMaxBytes {
				result.Truncated = true
				return false
			}
			m := combinedLogPattern.FindStringSubmatch(line)
			if len(m) != 7 {
				return true
			}
			stamp, parseErr := time.Parse("02/Jan/2006:15:04:05 -0700", m[2])
			if parseErr != nil || stamp.Before(startAt) || stamp.After(endAt) {
				return true
			}
			security := strings.HasPrefix(filepath.Base(path), "wp-security.log")
			matched := false
			switch kind {
			case "status":
				matched = !security && m[5] == value
			case "path":
				matched = !security && normalizeLogPath(m[4]) == value
			case "bot":
				name, verification := identifySearchBot(checker, m[6], m[1])
				matched = name+":"+verification == value
				if matched {
					requestKey := m[2] + "|" + m[1] + "|" + m[4] + "|" + m[6]
					if _, exists := seenBots[requestKey]; exists {
						matched = false
					} else {
						seenBots[requestKey] = struct{}{}
					}
				}
			case "ip":
				matched = !security && m[1] == value
			case "category":
				matched = !security && classifyLogTraffic(m[3], m[4], m[5], m[6], m[1], checker) == value
			}
			if matched {
				normalizedPath := normalizeLogPath(m[4])
				ips[m[1]]++
				paths[normalizedPath]++
				statuses[m[5]]++
				userAgents[normalizeUserAgent(m[6])]++
				methods[m[3]]++
				hourly[stamp.Format("2006-01-02 15:00")]++
				ipPathPairs[m[1]+" → "+normalizedPath]++
				if result.Total >= offset && len(result.Lines) < pageSize {
					result.Lines = append(result.Lines, sanitizeLogSample(line))
				}
				result.Total++
			}
			return true
		})
		if err != nil {
			return nil, fmt.Errorf("scan %s: %w", filepath.Base(path), err)
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	result.BytesScanned = bytesScanned
	result.UniqueIPs = len(ips)
	result.UniquePaths = len(paths)
	result.TopPaths = sortedCounts(paths, logAnalysisTopLimit)
	result.StatusCodes = sortedCounts(statuses, logAnalysisTopLimit)
	result.UserAgents = sortedCounts(userAgents, logAnalysisTopLimit)
	result.Methods = sortedCounts(methods, logAnalysisTopLimit)
	result.Hourly = sortedNamedCounts(hourly)
	result.IPPathPairs = sortedCounts(ipPathPairs, logAnalysisTopLimit)
	result.TopIPs = buildLogAnalysisIPDetailsContext(ctx, db, site.ID, ips, startAt, endAt)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

func normalizeUserAgent(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "-"
	}
	if len(value) > 160 {
		return value[:160]
	}
	return value
}

func buildLogAnalysisIPDetails(db *sql.DB, siteID int, counts map[string]int, startAt, endAt time.Time) []models.LogAnalysisIPDetail {
	return buildLogAnalysisIPDetailsContext(context.Background(), db, siteID, counts, startAt, endAt)
}

func buildLogAnalysisIPDetailsContext(ctx context.Context, db *sql.DB, siteID int, counts map[string]int, startAt, endAt time.Time) []models.LogAnalysisIPDetail {
	ranked := sortedCounts(counts, logAnalysisTopLimit)
	items := make([]models.LogAnalysisIPDetail, 0, len(ranked))
	for _, rankedIP := range ranked {
		item := models.LogAnalysisIPDetail{IPAddress: rankedIP.Name, Count: rankedIP.Count, SecurityEventTypes: []string{}}
		if db != nil {
			var expires sql.NullString
			_ = db.QueryRowContext(ctx, `SELECT reason,source_jail,expires_at FROM firewall_bans
				WHERE ip_address=? AND unbanned_at IS NULL AND (expires_at IS NULL OR expires_at > datetime('now'))
				ORDER BY banned_at DESC,id DESC LIMIT 1`, rankedIP.Name).Scan(&item.CurrentBanReason, &item.CurrentBanSource, &expires)
			if item.CurrentBanSource != "" || item.CurrentBanReason != "" || expires.Valid {
				item.CurrentlyBanned = true
				item.CurrentBanExpires = expires.String
			}
			var started, ended, historicalExpires sql.NullString
			_ = db.QueryRowContext(ctx, `SELECT reason,source_jail,banned_at,expires_at,unbanned_at,ban_count
				FROM firewall_bans WHERE ip_address=? AND banned_at <= ?
				AND COALESCE(unbanned_at,expires_at,datetime('now')) >= ?
				ORDER BY banned_at DESC,id DESC LIMIT 1`, rankedIP.Name,
				endAt.UTC().Format("2006-01-02 15:04:05"), startAt.UTC().Format("2006-01-02 15:04:05")).
				Scan(&item.RangeBanReason, &item.RangeBanSource, &started, &historicalExpires, &ended, &item.RangeBanCount)
			if started.Valid {
				item.BannedInRange = true
				item.RangeBanStartedAt = started.String
				item.RangeBanExpiresAt = historicalExpires.String
				item.RangeBanEndedAt = ended.String
			}
			rows, err := db.QueryContext(ctx, `SELECT event_type,COUNT(*),MAX(occurred_at) FROM wp_security_events
				WHERE site_id=? AND ip_address=? GROUP BY event_type ORDER BY COUNT(*) DESC,event_type ASC`, siteID, rankedIP.Name)
			if err == nil {
				for rows.Next() {
					var eventType, lastSeen string
					var count int
					if rows.Scan(&eventType, &count, &lastSeen) == nil {
						item.RetainedEventCount += count
						item.SecurityEventTypes = append(item.SecurityEventTypes, eventType)
						if lastSeen > item.LastSecurityEvent {
							item.LastSecurityEvent = lastSeen
						}
					}
				}
				rows.Close()
			}
		}
		items = append(items, item)
	}
	return items
}

func scanLogAnalysisDetailFile(path string, consume func(string) bool) error {
	return scanLogAnalysisDetailFileContext(context.Background(), path, consume)
}

func scanLogAnalysisDetailFileContext(ctx context.Context, path string, consume func(string) bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	var reader io.Reader = f
	if strings.HasSuffix(path, ".gz") {
		gz, gzipErr := gzip.NewReader(f)
		if gzipErr != nil {
			return gzipErr
		}
		defer gz.Close()
		reader = gz
	}
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !consume(scanner.Text()) {
			break
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	return ctx.Err()
}
