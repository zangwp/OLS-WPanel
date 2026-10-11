package handlers

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"net"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/zangwp/OLS-WPanel/internal/database"
)

const backupMaintenanceRequestBytes = 64 << 10

type backupMaintenanceSite struct {
	ID   int
	Root string
}

type backupMaintenanceRequest struct {
	SiteID     *int   `json:"site_id"`
	DestSiteID *int   `json:"dest_site_id"`
	RunAsUser  string `json:"run_as_user"`
	Path       string `json:"path"`
	OldPath    string `json:"old_path"`
	SrcPath    string `json:"src_path"`
	DestPath   string `json:"dest_path"`
	UploadID   string `json:"upload_id"`
}

// WebsiteBackupMaintenanceGuard rejects new writes while a whole-site backup or
// recovery retains its durable maintenance state. Mount it on the authenticated
// panel group, the separately authenticated Adminer group, and the localhost
// plugin group. It does not acquire operation locks: the coordinator must still
// drain in-flight writers and enforce its filesystem/database freeze.
func WebsiteBackupMaintenanceGuard() gin.HandlerFunc {
	return func(c *gin.Context) {
		route := backupMaintenanceRoute(c.FullPath())
		adminer := strings.HasPrefix(route, "/tools/adminer/")
		write := c.Request.Method != http.MethodGet && c.Request.Method != http.MethodHead && c.Request.Method != http.MethodOptions
		if !adminer && !write {
			c.Next()
			return
		}
		if c.Request.Method == http.MethodPost && route == "/api/websites/:id/site-backups/recover-maintenance" {
			// Only the dedicated coordinator may verify the durable journal and
			// release maintenance. Its handler still checks status and task gates;
			// ordinary database/file/site restores receive no exemption.
			c.Next()
			return
		}
		if c.Request.Method == http.MethodDelete && backupMaintenanceArchiveDelete(route) {
			// Archive deletion has its own operation/kernel locks and never
			// unfreezes the website. Keep backup management available.
			c.Next()
			return
		}
		if !adminer && !backupMaintenanceRelevantRoute(route) {
			c.Next()
			return
		}
		db := database.GetDB()
		ctx, cancel := context.WithTimeout(c.Request.Context(), 4*time.Second)
		defer cancel()
		frozen, err := loadBackupMaintenanceSites(ctx, db)
		if err != nil {
			backupMaintenanceReject(c, http.StatusServiceUnavailable, "backup_maintenance_unavailable")
			return
		}
		if len(frozen) == 0 {
			c.Next()
			return
		}
		blocked := backupMaintenanceGlobalWrite(route) || backupMaintenanceSharedSiteWrite(route)
		if !blocked {
			switch {
			case adminer || strings.HasPrefix(route, "/api/websites/:id"):
				var id int
				id, err = strconv.Atoi(c.Param("id"))
				if err == nil {
					blocked = backupMaintenanceHasSite(frozen, id)
				}
			case strings.HasPrefix(route, "/api/files/"):
				blocked, err = backupMaintenanceFileWrite(c, frozen)
			case route == "/api/cron" || strings.HasPrefix(route, "/api/cron/"):
				blocked, err = backupMaintenanceCronWrite(c, ctx, db, frozen)
			case strings.HasPrefix(route, "/api/sites/"):
				blocked, err = backupMaintenancePluginWrite(c, ctx, db, frozen)
			}
		}
		if err != nil {
			// Never pass an unresolved target to a write handler while a site is
			// frozen. Avoid returning SQL, paths, API keys, or request contents.
			backupMaintenanceReject(c, http.StatusServiceUnavailable, "backup_maintenance_unavailable")
			return
		}
		if blocked {
			backupMaintenanceReject(c, http.StatusConflict, "backup_maintenance")
			return
		}
		c.Next()
	}
}

func backupMaintenanceReject(c *gin.Context, status int, code string) {
	c.Header("Cache-Control", "no-store")
	c.AbortWithStatusJSON(status, gin.H{"success": false, "code": code, "message": "整站备份或恢复维护尚未结束，暂不能修改网站；请等待任务完成或核对维护恢复状态"})
}

func backupMaintenanceRoute(route string) string {
	for _, prefix := range []string{"/api/", "/tools/adminer/"} {
		if at := strings.Index(route, prefix); at >= 0 {
			return route[at:]
		}
	}
	return route
}

func backupMaintenanceRelevantRoute(route string) bool {
	return strings.HasPrefix(route, "/api/websites") || strings.HasPrefix(route, "/api/files/") ||
		strings.HasPrefix(route, "/api/cron") || strings.HasPrefix(route, "/api/sites/") ||
		backupMaintenanceGlobalWrite(route)
}

func backupMaintenanceArchiveDelete(route string) bool {
	switch route {
	case "/api/websites/:id/backups/:bid", "/api/websites/:id/file-backups/:bid", "/api/websites/:id/site-backups/:bid":
		return true
	}
	return false
}

func backupMaintenanceGlobalWrite(route string) bool {
	switch route {
	case "/api/websites", "/api/wp-fleet/inventory-refresh", "/api/backups/policy",
		"/api/settings", "/api/settings/panel-certificate", "/api/settings/db-backup/restore",
		"/api/software/opcache/clear", "/api/software/guard/action", "/api/software/config",
		"/api/software/php-config", "/api/software/php-runtimes/install", "/api/software/development-tools/install",
		"/api/update/do", "/api/system/updates/do", "/api/security/settings", "/api/security/whitelist/refresh",
		"/api/security/whitelist/googlebot", "/api/security/cdn-realip-groups", "/api/security/cdn-realip-groups/:id":
		return true
	}
	return false
}

// These otherwise site-scoped operations can restart/rebuild the shared OLS
// configuration. A write for another site must not remove the coordinator's
// temporary maintenance vhost or restart its PHP runtime mid-snapshot.
func backupMaintenanceSharedSiteWrite(route string) bool {
	switch route {
	case "/api/websites/:id/status", "/api/websites/:id/domains", "/api/websites/:id/ssl",
		"/api/websites/:id/cache", "/api/websites/:id/litespeed-cache/migrate",
		"/api/websites/:id/document-root", "/api/websites/:id/php-version", "/api/websites/:id/cdn-realip",
		"/api/websites/:id", "/api/sites/clear-cache", "/api/sites/cache-settings":
		return true
	}
	return false
}

func loadBackupMaintenanceSites(ctx context.Context, db *sql.DB) ([]backupMaintenanceSite, error) {
	if db == nil {
		return nil, errors.New("database unavailable")
	}
	rows, err := db.QueryContext(ctx, "SELECT id,web_root FROM websites WHERE status='backup_maintenance'")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var sites []backupMaintenanceSite
	for rows.Next() {
		var site backupMaintenanceSite
		if err = rows.Scan(&site.ID, &site.Root); err != nil {
			return nil, err
		}
		sites = append(sites, site)
	}
	return sites, rows.Err()
}

func backupMaintenanceHasSite(sites []backupMaintenanceSite, id int) bool {
	for _, site := range sites {
		if site.ID == id {
			return true
		}
	}
	return false
}

func backupMaintenanceReadJSON(c *gin.Context, value any) error {
	if c.Request.Body == nil {
		return io.EOF
	}
	original := c.Request.Body
	data, err := io.ReadAll(io.LimitReader(original, backupMaintenanceRequestBytes+1))
	// Restore the original bytes for the real handler, including the unread
	// remainder when the gate rejects an oversized request.
	c.Request.Body = &backupMaintenanceReplayBody{Reader: io.MultiReader(bytes.NewReader(data), original), closer: original}
	if err != nil || len(data) > backupMaintenanceRequestBytes {
		return errors.New("cannot inspect request")
	}
	return json.Unmarshal(data, value)
}

type backupMaintenanceReplayBody struct {
	io.Reader
	closer io.Closer
}

func (body *backupMaintenanceReplayBody) Close() error { return body.closer.Close() }

func backupMaintenancePluginWrite(c *gin.Context, ctx context.Context, db *sql.DB, sites []backupMaintenanceSite) (bool, error) {
	host, _, err := net.SplitHostPort(c.Request.RemoteAddr)
	key := c.GetHeader("X-OLS-WPanel-Key")
	if err != nil || (host != "127.0.0.1" && host != "::1") || key == "" {
		return false, errors.New("invalid plugin identity")
	}
	var id, count int
	err = db.QueryRowContext(ctx, "SELECT COALESCE(MIN(id),0),COUNT(*) FROM websites WHERE plugin_api_key=? AND plugin_api_key<>''", key).Scan(&id, &count)
	if err != nil || count != 1 {
		return false, errors.New("unresolved plugin identity")
	}
	return backupMaintenanceHasSite(sites, id), nil
}

func backupMaintenanceCronOwner(ctx context.Context, db *sql.DB, sites []backupMaintenanceSite, siteID *int, user string) (bool, error) {
	if siteID != nil && *siteID > 0 && backupMaintenanceHasSite(sites, *siteID) {
		return true, nil
	}
	user = strings.TrimSpace(user)
	if user == "" || user == "root" {
		// A root/unowned command can write any website regardless of an
		// optional site_id. Never try to prove arbitrary shell text safe.
		return true, nil
	}
	var frozenCount, total int
	err := db.QueryRowContext(ctx, "SELECT COUNT(*),COALESCE(SUM(CASE WHEN status='backup_maintenance' THEN 1 ELSE 0 END),0) FROM websites WHERE system_user=?", user).Scan(&total, &frozenCount)
	if err != nil {
		return false, err
	}
	if total != 1 {
		return true, nil
	}
	return frozenCount > 0, nil
}

func backupMaintenanceCronWrite(c *gin.Context, ctx context.Context, db *sql.DB, sites []backupMaintenanceSite) (bool, error) {
	if c.Param("id") != "" {
		var id sql.NullInt64
		var user, taskType string
		err := db.QueryRowContext(ctx, "SELECT site_id,COALESCE(run_as_user,''),task_type FROM cron_jobs WHERE id=?", c.Param("id")).Scan(&id, &user, &taskType)
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil // The handler reports its existing not-found error.
		}
		if err != nil {
			return false, err
		}
		var siteID *int
		if id.Valid {
			value := int(id.Int64)
			siteID = &value
		}
		blocked := siteID != nil && backupMaintenanceHasSite(sites, *siteID)
		if !blocked && taskType == "command" {
			blocked, err = backupMaintenanceCronOwner(ctx, db, sites, siteID, user)
		}
		if blocked || err != nil || c.Request.Method != http.MethodPut {
			return blocked, err
		}
	}
	var req struct {
		backupMaintenanceRequest
		TaskType string `json:"task_type"`
	}
	if err := backupMaintenanceReadJSON(c, &req); err != nil {
		return false, err
	}
	if req.SiteID != nil && backupMaintenanceHasSite(sites, *req.SiteID) {
		return true, nil
	}
	if req.TaskType != "" && req.TaskType != "command" {
		return false, nil
	}
	return backupMaintenanceCronOwner(ctx, db, sites, req.SiteID, req.RunAsUser)
}

func backupMaintenanceUploadID(c *gin.Context) (string, error) {
	_, params, err := mime.ParseMediaType(c.GetHeader("Content-Type"))
	if err != nil || params["boundary"] == "" || c.Request.Body == nil {
		return "", errors.New("invalid upload metadata")
	}
	original := c.Request.Body
	var prefix bytes.Buffer
	r := multipart.NewReader(io.TeeReader(io.LimitReader(original, backupMaintenanceRequestBytes), &prefix), params["boundary"])
	defer func() {
		c.Request.Body = &backupMaintenanceReplayBody{Reader: io.MultiReader(bytes.NewReader(prefix.Bytes()), original), closer: original}
	}()
	for {
		part, partErr := r.NextPart()
		if partErr != nil || part.FileName() != "" {
			return "", errors.New("upload identity must precede file data")
		}
		if part.FormName() == "upload_id" {
			value, readErr := io.ReadAll(io.LimitReader(part, 257))
			if readErr != nil || len(value) == 0 || len(value) > 256 {
				return "", errors.New("invalid upload identity")
			}
			return string(value), nil
		}
	}
}

func backupMaintenanceFileWrite(c *gin.Context, sites []backupMaintenanceSite) (bool, error) {
	var req backupMaintenanceRequest
	route := backupMaintenanceRoute(c.FullPath())
	queryTarget := false
	switch route {
	case "/api/files/upload", "/api/files/delete", "/api/files/zip", "/api/files/unzip", "/api/files/mkdir", "/api/files/fix-permissions":
		queryTarget = true
	}
	if route == "/api/files/upload/chunk" {
		var err error
		req.UploadID, err = backupMaintenanceUploadID(c)
		if err != nil {
			return false, err
		}
	} else if !queryTarget {
		// These handlers explicitly call ShouldBindJSON, even if the caller
		// omits or lies about Content-Type. Apply the same selector contract.
		if err := backupMaintenanceReadJSON(c, &req); err != nil {
			return false, err
		}
	}
	if route == "/api/files/upload/chunk" || route == "/api/files/upload/complete" {
		if req.UploadID == "" || filepath.Base(req.UploadID) != req.UploadID || strings.ContainsAny(req.UploadID, `/\\`) {
			return false, errors.New("invalid upload session")
		}
		session, err := loadUploadSession(uploadSessionDir(req.UploadID))
		if err != nil {
			return false, err
		}
		req.SiteID, req.Path = &session.SiteID, session.Path
	}
	if queryTarget {
		// Match the handler's authoritative selector. Query parameters must
		// never override JSON selectors on rename/copy/remote-import, and
		// ignored JSON fields must not override query-based targets either.
		id, err := strconv.Atoi(c.Query("site_id"))
		if err != nil || id < 0 {
			return false, errors.New("invalid file target")
		}
		req.SiteID, req.Path = &id, c.Query("path")
		req.DestSiteID, req.OldPath, req.SrcPath, req.DestPath = nil, "", "", ""
	}
	if req.SiteID == nil {
		id := 0 // Existing file endpoints use the backup directory by default.
		req.SiteID = &id
	}
	checks := []struct {
		id    int
		paths []string
	}{{*req.SiteID, []string{req.Path, req.OldPath, req.SrcPath}}}
	if req.DestSiteID != nil {
		checks = append(checks, struct {
			id    int
			paths []string
		}{*req.DestSiteID, []string{req.DestPath}})
	} else if req.DestPath != "" {
		checks[0].paths = append(checks[0].paths, req.DestPath)
	}
	for _, check := range checks {
		if backupMaintenanceHasSite(sites, check.id) {
			return true, nil
		}
		base, err := fileBasePath(check.id)
		if err != nil {
			return false, err
		}
		for _, path := range check.paths {
			target, err := resolvePathForAccess(filepath.Join(base, path))
			if err != nil {
				return false, err
			}
			for _, site := range sites {
				root, err := resolvePathForAccess(site.Root)
				if err != nil || !filepath.IsAbs(root) {
					return false, errors.New("cannot resolve maintained root")
				}
				if backupMaintenancePathsOverlap(root, target) {
					return true, nil
				}
			}
		}
	}
	return false, nil
}

func backupMaintenancePathsOverlap(a, b string) bool {
	for _, pair := range [][2]string{{a, b}, {b, a}} {
		rel, err := filepath.Rel(pair[0], pair[1])
		if err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel) {
			return true
		}
	}
	return false
}
