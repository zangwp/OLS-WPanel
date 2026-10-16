package executor

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/zangwp/OLS-WPanel/internal/config"
	"github.com/zangwp/OLS-WPanel/internal/database"
	"github.com/zangwp/OLS-WPanel/internal/models"
)

const pluginDirName = "ols-wpanel-optimizer"

var setCompanionPluginPermissions = InstallPluginPermissions
var regenerateSiteOLSForCache = RegenerateSiteOLSConfig

var errCompanionRemovedBeforePublish = errors.New("installed companion was removed before publish")

// cacheHelperPluginFS stores startup-provided assets for site deployment and version checks.
// EnsureCacheHelperPlugin initializes it.
var cacheHelperPluginFS fs.FS

// EnsureCacheHelperPlugin syncs embedded assets to /www/ols-wpanel/packages/ols-wpanel-optimizer/.
// This reference copy only supports version checks and serves no sites, so content-based sync is sufficient.
func EnsureCacheHelperPlugin(pluginFS fs.FS) {
	cacheHelperPluginFS = pluginFS
	pkgDir := "/www/ols-wpanel/packages"
	refDir := filepath.Join(pkgDir, pluginDirName)
	os.MkdirAll(pkgDir, 0755)

	// Remove the legacy single-file reference copy.
	os.Remove(filepath.Join(pkgDir, pluginDirName+".php"))

	srcFiles, err := readEmbeddedPluginFiles(pluginFS)
	if err != nil || len(srcFiles) == 0 {
		return
	}

	seen := make(map[string]bool, len(srcFiles))
	for rel, data := range srcFiles {
		seen[rel] = true
		dst := filepath.Join(refDir, filepath.FromSlash(rel))
		if existing, err := os.ReadFile(dst); err == nil && bytes.Equal(existing, data) {
			continue
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
			continue
		}
		os.WriteFile(dst, data, 0644)
	}

	// Remove reference files no longer present in the embedded source.
	filepath.WalkDir(refDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		rel, relErr := filepath.Rel(refDir, path)
		if relErr == nil && !seen[filepath.ToSlash(rel)] {
			os.Remove(path)
		}
		return nil
	})
}

// AutoDeployPluginUpdates updates outdated companion plugins on running WordPress sites,
// including inactive plugins. plugin_api_key selects managed sites but does not prove installation.
// Called at panel startup.
func AutoDeployPluginUpdates(pluginFS fs.FS) {
	srcFiles, version, err := embeddedPluginFilesWithVersion(pluginFS)
	if err != nil || len(srcFiles) == 0 {
		return
	}

	db := database.GetDB()
	rows, err := db.Query(`SELECT id FROM websites
		WHERE site_type = 'wordpress' AND status = 'active' AND plugin_api_key != ''`)
	if err != nil {
		return
	}
	var ids []int
	for rows.Next() {
		var id int
		if rows.Scan(&id) == nil {
			ids = append(ids, id)
		}
	}
	rows.Close()
	var updated int
	for _, id := range ids {
		if !TryAcquireCompanionDeployLock(id) {
			continue
		}
		changed, err := deploySiteCompanionOwned(id, srcFiles, version, true)
		ReleaseSiteOpLock(id)
		if err != nil {
			log.Printf("[插件自动更新] 部署失败 site=%d: %v", id, err)
			continue
		}
		if changed {
			updated++
		}
	}
	if updated > 0 {
		log.Printf("[插件自动更新] 已更新 %d 个站点的配套插件", updated)
	}
}

// DeploySiteCompanionPluginOwned is restricted to the embedded companion. The
// caller owns the shared site lock for the entire deployment/identity workflow.
func DeploySiteCompanionPluginOwned(siteID int) error {
	files, version, err := embeddedPluginFilesWithVersion(cacheHelperPluginFS)
	if err != nil || len(files) == 0 {
		return fmt.Errorf("embedded companion unavailable")
	}
	_, err = deploySiteCompanionOwned(siteID, files, version, false)
	return err
}

// UpdateExistingSiteCompanionPluginOwned updates only an installed companion.
// It never turns a deleted plugin into a new installation.
func UpdateExistingSiteCompanionPluginOwned(siteID int) (bool, string, error) {
	files, version, err := embeddedPluginFilesWithVersion(cacheHelperPluginFS)
	if err != nil || len(files) == 0 {
		return false, "", fmt.Errorf("embedded companion unavailable")
	}
	changed, err := deploySiteCompanionOwned(siteID, files, version, true)
	return changed, companionPluginReleaseVersion(files), err
}

func CompanionPluginVersion() string {
	files, err := readEmbeddedPluginFiles(cacheHelperPluginFS)
	if err != nil {
		return ""
	}
	return companionPluginReleaseVersion(files)
}

var companionPluginVersionPattern = regexp.MustCompile(`(?m)^\s*\*\s*Version:\s*([^\s]+)\s*$`)

func companionPluginReleaseVersion(files map[string][]byte) string {
	match := companionPluginVersionPattern.FindSubmatch(files[pluginDirName+".php"])
	if len(match) != 2 {
		return ""
	}
	return string(match[1])
}

func deploySiteCompanionOwned(siteID int, files map[string][]byte, version string, requireExisting bool) (bool, error) {
	manager := DefaultMaintenanceManager()
	site, state, _, err := manager.load(siteID)
	if err != nil {
		return false, err
	}
	if site.SiteType != "wordpress" || site.Status != models.StatusActive || manager.isUncertain(siteID) || site.FileLockApplyStatus == "applying" || site.FileLockApplyStatus == "failed" {
		return false, ErrMaintenanceBusy
	}
	if err := manager.companionDeployConflicts(siteID); err != nil {
		return false, err
	}
	root, err := safeSiteWebRoot(site.WebRoot)
	if err != nil {
		return false, err
	}
	pluginsDir := filepath.Join(root, "wp-content", "plugins")
	pluginDir := filepath.Join(pluginsDir, pluginDirName)
	for _, path := range []string{site.WebRoot, filepath.Join(root, "wp-content"), pluginsDir, pluginDir} {
		if err := rejectSymlinkPath(path); err != nil {
			return false, err
		}
	}
	if requireExisting {
		if err := requireExistingCompanion(pluginDir); errors.Is(err, errCompanionRemovedBeforePublish) {
			return false, nil
		} else if err != nil {
			return false, err
		}
	}
	if site.FileLockEnabled && site.FileLockApplyStatus != "ready" {
		return false, ErrMaintenanceUnknown
	}
	if pluginDeployedVersion(pluginDir) == version {
		return false, nil
	}
	var prepare func(string) error
	if site.FileLockEnabled {
		_, gid, err := siteUserIDs(site.SystemUser)
		if err != nil {
			return false, err
		}
		prepare = func(staging string) error { return sealCompanionDirectory(staging, gid) }
	} else {
		prepare = func(staging string) error { return setCompanionPluginPermissions("", site.SystemUser, staging) }
	}
	var beforePublish func() error
	if requireExisting {
		beforePublish = func() error { return requireExistingCompanion(pluginDir) }
	}
	if err := deployPluginDirectoryPrepared(pluginsDir, pluginDir, files, prepare, beforePublish); err != nil {
		if errors.Is(err, errCompanionRemovedBeforePublish) {
			return false, nil
		}
		return false, err
	}
	if site.FileLockEnabled && state.Window == nil {
		refreshWPCodeIntegrityBaselineBestEffort(site.ID, "配套插件更新成功")
	}
	return true, nil
}

func requireExistingCompanion(pluginDir string) error {
	info, err := os.Lstat(filepath.Join(pluginDir, pluginDirName+".php"))
	if os.IsNotExist(err) {
		return errCompanionRemovedBeforePublish
	}
	if err != nil || !info.Mode().IsRegular() {
		return fmt.Errorf("installed companion entry unavailable")
	}
	return nil
}

// Publish-ready permissions: no whole-site unlock and no writable published
// interval. Uses the same owner/mode primitive as the existing file lock.
func sealCompanionDirectory(dir string, gid int) error {
	return filepath.WalkDir(dir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("companion symlink rejected")
		}
		mode := os.FileMode(0444)
		if entry.IsDir() {
			mode = 0555
		}
		return applyOwnerMode(path, 0, gid, mode)
	})
}

// PluginNeedsUpdate compares the site's plugin with the embedded version.
// needsUpdate is meaningful only when installed is true.
func PluginNeedsUpdate(webRoot string) (installed bool, needsUpdate bool) {
	pluginDir := filepath.Join(webRoot, "wp-content", "plugins", pluginDirName)
	if _, err := os.Stat(filepath.Join(pluginDir, pluginDirName+".php")); err != nil {
		return false, false
	}
	_, version, err := embeddedPluginFilesWithVersion(cacheHelperPluginFS)
	if err != nil {
		return true, false
	}
	return true, pluginDeployedVersion(pluginDir) != version
}

// readEmbeddedPluginFiles maps relative plugin paths to embedded file contents.
func readEmbeddedPluginFiles(pluginFS fs.FS) (map[string][]byte, error) {
	if pluginFS == nil {
		return nil, fs.ErrNotExist
	}
	const root = "ols-wpanel-optimizer"
	files := make(map[string][]byte)
	err := fs.WalkDir(pluginFS, root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		data, err := fs.ReadFile(pluginFS, path)
		if err != nil {
			return err
		}
		files[filepath.ToSlash(rel)] = data
		return nil
	})
	if err != nil {
		return nil, err
	}
	return files, nil
}

// pluginVersionMarkerFile stores pluginSourceVersion() in each deployed plugin directory.
// Comparing one marker avoids reading and comparing every plugin file at startup.
// Its dot prefix keeps it outside WordPress get_plugins() discovery.
const pluginVersionMarkerFile = ".olsw-version"

// embeddedPluginFilesWithVersion adds the version marker to the source map so both
// site deployment and local reference sync write it alongside the plugin files.
func embeddedPluginFilesWithVersion(pluginFS fs.FS) (map[string][]byte, string, error) {
	srcFiles, err := readEmbeddedPluginFiles(pluginFS)
	if err != nil {
		return nil, "", err
	}
	version := pluginSourceVersion(srcFiles)
	srcFiles[pluginVersionMarkerFile] = []byte(version)
	return srcFiles, version, nil
}

// pluginSourceVersion hashes sorted paths and contents, producing a stable version
// independent of Go map iteration order that changes whenever any source file changes.
func pluginSourceVersion(srcFiles map[string][]byte) string {
	rels := make([]string, 0, len(srcFiles))
	for rel := range srcFiles {
		rels = append(rels, rel)
	}
	sort.Strings(rels)
	h := sha256.New()
	for _, rel := range rels {
		h.Write([]byte(rel))
		h.Write([]byte{0})
		h.Write(srcFiles[rel])
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// pluginDeployedVersion reads a site's version marker. Missing directories or markers
// return an empty string, causing legacy deployments to update on the next comparison.
func pluginDeployedVersion(pluginDir string) string {
	data, err := os.ReadFile(filepath.Join(pluginDir, pluginVersionMarkerFile))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// deployPluginDirectory replaces pluginDir, which is usually nonempty and cannot be
// atomically overwritten by a single Linux rename. Clean stale directories, build on the same
// filesystem, move the current directory to backup, install the new directory, then remove backup.
// Roll back if installation fails. Dot-prefixed temporary/backup names are ignored by get_plugins().
func deployPluginDirectory(pluginsDir, pluginDir string, srcFiles map[string][]byte) error {
	return deployPluginDirectoryPrepared(pluginsDir, pluginDir, srcFiles, nil, nil)
}

func deployPluginDirectoryPrepared(pluginsDir, pluginDir string, srcFiles map[string][]byte, prepare func(string) error, beforePublish func() error) error {
	recoverOrCleanupStalePluginDirs(pluginsDir, pluginDir)

	suffix := NewCacheKey()
	stagingDir := filepath.Join(pluginsDir, "."+pluginDirName+".staging-"+suffix)
	backupDir := filepath.Join(pluginsDir, "."+pluginDirName+".backup-"+suffix)

	if err := writePluginFiles(stagingDir, srcFiles); err != nil {
		os.RemoveAll(stagingDir)
		return fmt.Errorf("构建临时目录失败: %w", err)
	}
	if prepare != nil {
		if err := prepare(stagingDir); err != nil {
			os.RemoveAll(stagingDir)
			return fmt.Errorf("准备插件权限失败: %w", err)
		}
	}
	if beforePublish != nil {
		if err := beforePublish(); err != nil {
			os.RemoveAll(stagingDir)
			return err
		}
	}

	targetExists := false
	if _, err := os.Stat(pluginDir); err == nil {
		targetExists = true
	}

	if targetExists {
		if err := os.Rename(pluginDir, backupDir); err != nil {
			os.RemoveAll(stagingDir)
			return fmt.Errorf("移走旧目录失败: %w", err)
		}
	}

	if err := os.Rename(stagingDir, pluginDir); err != nil {
		if targetExists {
			if rollbackErr := os.Rename(backupDir, pluginDir); rollbackErr != nil {
				return fmt.Errorf("部署失败且回滚失败，插件目录可能已丢失，需人工检查 %s: 回滚错误=%v 原始错误=%v", pluginDir, rollbackErr, err)
			}
		}
		os.RemoveAll(stagingDir)
		return fmt.Errorf("替换插件目录失败（已回滚到部署前状态）: %w", err)
	}

	if targetExists {
		logUnexpectedPluginFiles(backupDir, srcFiles)
		os.RemoveAll(backupDir)
	}
	return nil
}

// logUnexpectedPluginFiles records files absent from source before discarding the backup.
// They are not preserved: deployment must exactly match the embedded source.
func logUnexpectedPluginFiles(backupDir string, srcFiles map[string][]byte) {
	var extra []string
	filepath.WalkDir(backupDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		rel, relErr := filepath.Rel(backupDir, path)
		if relErr != nil {
			return nil
		}
		if _, ok := srcFiles[filepath.ToSlash(rel)]; !ok {
			extra = append(extra, filepath.ToSlash(rel))
		}
		return nil
	})
	if len(extra) > 0 {
		log.Printf("[插件部署] 发现 %d 个源码之外的文件，本次更新会一并移除: %v", len(extra), extra)
	}
}

// recoverOrCleanupStalePluginDirs handles interrupted deployments. If the plugin directory
// is missing but its backup exists, restore the backup before cleaning stale directories;
// the process may have stopped after moving the old directory but before installing the new one.
func recoverOrCleanupStalePluginDirs(pluginsDir, pluginDir string) {
	stagingPrefix := "." + pluginDirName + ".staging-"
	backupPrefix := "." + pluginDirName + ".backup-"

	if _, statErr := os.Stat(pluginDir); os.IsNotExist(statErr) {
		if entries, err := os.ReadDir(pluginsDir); err == nil {
			for _, entry := range entries {
				if !entry.IsDir() || !strings.HasPrefix(entry.Name(), backupPrefix) {
					continue
				}
				backupPath := filepath.Join(pluginsDir, entry.Name())
				if renameErr := os.Rename(backupPath, pluginDir); renameErr == nil {
					log.Printf("[插件自动更新] 检测到上次部署中断，已从备份目录恢复插件: %s", pluginDir)
					break
				}
			}
		}
	}

	entries, err := os.ReadDir(pluginsDir)
	if err != nil {
		return
	}
	for _, entry := range entries {
		if entry.IsDir() && (strings.HasPrefix(entry.Name(), stagingPrefix) || strings.HasPrefix(entry.Name(), backupPrefix)) {
			os.RemoveAll(filepath.Join(pluginsDir, entry.Name()))
		}
	}
}

func writePluginFiles(dir string, files map[string][]byte) error {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	for rel, data := range files {
		dst := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
			return err
		}
		if err := os.WriteFile(dst, data, 0644); err != nil {
			return err
		}
	}
	return nil
}

func NewCacheKey() string {
	b := make([]byte, 4)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func NewAPIKey() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func UpdateSiteLiteSpeedCache(siteID, enabled, ttl int) error {
	db := database.GetDB()
	var oldEnabled, oldTTL int
	var siteType string
	if err := db.QueryRow(`SELECT litespeed_cache_enabled, litespeed_cache_ttl, site_type FROM websites WHERE id=?`, siteID).Scan(&oldEnabled, &oldTTL, &siteType); err != nil {
		return fmt.Errorf("读取原缓存设置失败: %w", err)
	}
	if siteType == "wordpress" {
		// Legacy clients may still send the old server-cache switch. WordPress
		// uses the plugin's response policy, never blanket public caching.
		enabled = 0
	}
	result, err := db.Exec(`UPDATE websites SET litespeed_cache_enabled=?, litespeed_cache_ttl=? WHERE id=?`, enabled, ttl, siteID)
	if err != nil {
		return fmt.Errorf("保存缓存设置失败: %w", err)
	}
	if affected, err := result.RowsAffected(); err != nil || affected != 1 {
		if err != nil {
			return fmt.Errorf("确认缓存设置失败: %w", err)
		}
		return errors.New("网站不存在")
	}
	return publishSiteOLSWithCacheRollback(siteID, oldEnabled, oldTTL)
}

func publishSiteOLSWithCacheRollback(siteID, oldEnabled, oldTTL int) error {
	if err := regenerateSiteOLSForCache(siteID); err == nil {
		return nil
	} else {
		applyErr := err
		if _, rollbackErr := database.GetDB().Exec(`UPDATE websites SET litespeed_cache_enabled=?, litespeed_cache_ttl=? WHERE id=?`, oldEnabled, oldTTL, siteID); rollbackErr != nil {
			return fmt.Errorf("应用 OpenLiteSpeed 配置失败: %v；恢复缓存设置失败: %w", applyErr, rollbackErr)
		}
		if rollbackErr := regenerateSiteOLSForCache(siteID); rollbackErr != nil {
			return fmt.Errorf("应用 OpenLiteSpeed 配置失败: %v；恢复旧配置失败: %w", applyErr, rollbackErr)
		}
		return fmt.Errorf("应用 OpenLiteSpeed 配置失败，缓存设置已恢复: %w", applyErr)
	}
}

func PublishSiteOLSWithCacheRollback(siteID, oldEnabled, oldTTL int) error {
	return publishSiteOLSWithCacheRollback(siteID, oldEnabled, oldTTL)
}

func ClearSiteCache(siteID int) error {
	db := database.GetDB()
	var oldKey, webRoot string
	if err := db.QueryRow(`SELECT litespeed_cache_key,web_root FROM websites WHERE id=?`, siteID).Scan(&oldKey, &webRoot); err != nil {
		return fmt.Errorf("读取缓存标识失败: %w", err)
	}
	key := NewCacheKey()
	if _, err := db.Exec("UPDATE websites SET litespeed_cache_key = ? WHERE id = ?", key, siteID); err != nil {
		return fmt.Errorf("更新缓存标识失败: %w", err)
	}
	if err := regenerateSiteOLSForCache(siteID); err != nil {
		if _, rollbackErr := db.Exec(`UPDATE websites SET litespeed_cache_key=? WHERE id=?`, oldKey, siteID); rollbackErr != nil {
			return fmt.Errorf("清除缓存应用失败: %v；恢复缓存标识失败: %w", err, rollbackErr)
		}
		if rollbackErr := regenerateSiteOLSForCache(siteID); rollbackErr != nil {
			return fmt.Errorf("清除缓存应用失败: %v；恢复旧 OpenLiteSpeed 配置失败: %w", err, rollbackErr)
		}
		return fmt.Errorf("清除缓存失败，原缓存标识已恢复: %w", err)
	}
	if config.AppConfig == nil || strings.TrimSpace(config.AppConfig.Paths.WWWRoot) == "" {
		return errors.New("面板网站根目录配置不可用")
	}
	for _, candidate := range []string{filepath.Join(webRoot, ".lscache"), filepath.Join(webRoot, "wp-content", "litespeed")} {
		path, err := managedSubpath(config.AppConfig.Paths.WWWRoot, candidate, "LiteSpeed 缓存目录")
		if err != nil {
			return err
		}
		if info, err := os.Lstat(path); err == nil {
			if info.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("拒绝清理符号链接缓存目录: %s", path)
			}
			if err := os.RemoveAll(path); err != nil {
				return fmt.Errorf("清理 LiteSpeed 缓存失败: %w", err)
			}
		} else if !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

func ClearWPSiteRuntimeCaches(siteID int, domain, webRoot string) {
	if err := ClearSiteCache(siteID); err != nil {
		log.Printf("清理 LiteSpeed 页面缓存失败 site=%d: %v", siteID, err)
	}
	if err := ClearWPRedisObjectCache(domain, webRoot); err != nil {
		log.Printf("清理 Redis Object Cache 失败 domain=%s: %v", domain, err)
	}
}

func ClearWPRedisObjectCache(domain, webRoot string) error {
	prefixes := redisObjectCachePrefixes(domain, webRoot)
	for _, prefix := range prefixes {
		if err := deleteRedisKeysByPrefix(prefix); err != nil {
			return err
		}
	}
	return nil
}

func redisObjectCachePrefixes(domain, webRoot string) []string {
	seen := make(map[string]bool)
	var prefixes []string
	add := func(prefix string) {
		prefix = strings.TrimSpace(prefix)
		if prefix == "" || seen[prefix] {
			return
		}
		seen[prefix] = true
		prefixes = append(prefixes, prefix)
	}

	if strings.TrimSpace(webRoot) != "" {
		if data, err := os.ReadFile(filepath.Join(webRoot, "wp-config.php")); err == nil {
			content := string(data)
			add(extractWPConfigStringConstant(content, "WP_REDIS_PREFIX"))
			add(extractWPConfigStringConstant(content, "WP_CACHE_KEY_SALT"))
		}
	}
	add(wpCacheKeySalt(domain))
	return prefixes
}

func extractWPConfigStringConstant(content, name string) string {
	re := regexp.MustCompile(`(?m)^\s*define\s*\(\s*['"]` + regexp.QuoteMeta(name) + `['"]\s*,\s*['"]([^'"]*)['"]\s*\)\s*;`)
	matches := re.FindStringSubmatch(content)
	if len(matches) != 2 {
		return ""
	}
	return matches[1]
}

func deleteRedisKeysByPrefix(prefix string) error {
	keys, err := exec.Command("redis-cli", "--scan", "--pattern", prefix+"*").Output()
	if err != nil {
		return err
	}

	var batch []string
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		args := append([]string{"DEL"}, batch...)
		batch = nil
		return exec.Command("redis-cli", args...).Run()
	}
	for _, key := range strings.Split(string(keys), "\n") {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		batch = append(batch, key)
		if len(batch) >= 200 {
			if err := flush(); err != nil {
				return err
			}
		}
	}
	return flush()
}

func RegenerateSiteOLSConfig(siteID int) error {
	db := database.GetDB()
	var domain, aliases, aliasRedirectMode, siteType, systemUser, webRoot, documentRootSubdir, logDir, accessLogMode, cacheKey, templateVer string
	var phpPoolPath, phpVersion, olsVHostConfigPath string
	var sslEnabled, lsCacheEnabled, xmlrpcEnabled, cdnRealIPEnabled int
	var lsCacheTTL, maxChildren int
	var sslCertPath, sslKeyPath, status string

	err := db.QueryRow(
		`SELECT domain, aliases, alias_redirect_mode, site_type, system_user, web_root, document_root_subdir, log_dir, ssl_enabled,
		        access_log_mode, litespeed_cache_enabled, litespeed_cache_ttl, litespeed_cache_key,
		        ssl_cert_path, ssl_key_path, template_version, xmlrpc_enabled, lsphp_socket_path, php_version, ols_vhost_config_path, cdn_realip_enabled, status, COALESCE(lsphp_max_children, 0)
		 FROM websites WHERE id = ?`, siteID,
	).Scan(&domain, &aliases, &aliasRedirectMode, &siteType, &systemUser, &webRoot, &documentRootSubdir, &logDir, &sslEnabled, &accessLogMode, &lsCacheEnabled, &lsCacheTTL, &cacheKey, &sslCertPath, &sslKeyPath, &templateVer, &xmlrpcEnabled, &phpPoolPath, &phpVersion, &olsVHostConfigPath, &cdnRealIPEnabled, &status, &maxChildren)
	if err != nil || domain == "" {
		if err != nil {
			return fmt.Errorf("查询站点失败(site %d): %w", siteID, err)
		}
		return fmt.Errorf("站点域名为空(site %d)", siteID)
	}

	if templateVer == "" {
		templateVer = "v1.0"
	}
	if cacheKey == "" {
		cacheKey = NewCacheKey()
		db.Exec("UPDATE websites SET litespeed_cache_key = ? WHERE id = ?", cacheKey, siteID)
	}

	cfg := config.AppConfig
	phpRuntime, err := ResolveLSPHPRuntime(phpVersion, false)
	if err != nil {
		return fmt.Errorf("PHP 运行时配置无效(site %d): %w", siteID, err)
	}
	engine := NewTemplateEngine(cfg.Panel.BackupDir)

	var aliasList []string
	if aliases != "" {
		aliasList = strings.Split(aliases, "\n")
	}

	data := &OLSVHostData{
		Domain:            domain,
		Aliases:           aliasList,
		AliasRedirectMode: aliasRedirectMode,
		ServerNames:       buildServerNames(domain, aliasList),
		WebRoot:           EffectiveDocumentRoot(webRoot, siteType, documentRootSubdir),
		LogDir:            logDir,
		SystemUser:        systemUser,
		SiteType:          siteType,
		PHPProxy:          "unix:" + phpSocketPath(cfg, phpPoolPath, domain),
		LSPHPBinary:       phpRuntime.LSAPIBinary,
		TemplateVer:       templateVer,
		AccessLogMode:     accessLogMode,
		UseSSL:            sslEnabled == 1,
		LSCacheEnabled:    lsCacheEnabled == 1,
		LSCacheTTL:        lsCacheTTL,
		LSCacheKey:        cacheKey,
		XMLRPCEnabled:     xmlrpcEnabled == 1,
		PHPMaxChildren:    maxChildren,
	}
	if cdnRealIPEnabled == 1 {
		groups, _ := GetWebsiteCDNRealIPGroups(siteID)
		runtime, err := ResolveCDNRealIPRuntime(&models.Website{ID: siteID, CDNRealIPEnabled: true, CDNRealIPGroups: groups})
		if err != nil {
			return fmt.Errorf("CDN Real IP 配置无效(site %d): %w", siteID, err)
		}
		if runtime.Enabled {
			data.CDNRealIPEnabled = true
			data.CDNRealIPHeader = runtime.HeaderName
			data.CDNRealIPRanges = runtime.IPRanges
			data.CDNRealIPCompat = runtime.Compatible
		}
	}
	if data.UseSSL {
		data.SSLCertPath = sslCertPath
		data.SSLKeyPath = sslKeyPath
	}

	config, err := engine.RenderOLSVHostConfig(data)
	if err != nil {
		return fmt.Errorf("渲染 OpenLiteSpeed 配置失败(site %d): %w", siteID, err)
	}
	var migrationLockCount int
	var migrationLockDirection, migrationSiteID, migrationStage string
	if err := db.QueryRow(`SELECT COUNT(*),COALESCE(MAX(ml.direction),''),COALESCE(MAX(ml.migration_site_id),''),COALESCE(MAX(ms.stage),'')
		FROM site_migration_locks ml JOIN site_migration_sites ms ON ms.id=ml.migration_site_id
		WHERE ml.status='active' AND ((? > 0 AND ml.site_id=?) OR ml.domain=?)`, siteID, siteID, strings.ToLower(strings.TrimSpace(domain))).Scan(&migrationLockCount, &migrationLockDirection, &migrationSiteID, &migrationStage); err != nil {
		return fmt.Errorf("检查站点迁移锁失败(site %d): %w", siteID, err)
	}
	if migrationLockCount > 1 {
		return fmt.Errorf("检查站点迁移锁失败(site %d): 发现多个活动锁", siteID)
	}
	if migrationLockDirection == "target" {
		block, enabledPath, err := loadPersistedSiteMigrationTargetMarkerBlock(context.Background(), db, migrationSiteID, migrationStage)
		if err != nil {
			return fmt.Errorf("恢复迁移目标标记失败(site %d): %w", siteID, err)
		}
		config, err = injectSiteMigrationTargetMarker(config, block)
		if err != nil {
			return fmt.Errorf("恢复迁移目标配置失败(site %d): %w", siteID, err)
		}
		if err := applyMigrationOLSVHostContent(olsVHostConfigPath, enabledPath, config); err != nil {
			return fmt.Errorf("应用迁移目标 OpenLiteSpeed 配置失败(site %d): %w", siteID, err)
		}
		return nil
	}
	if migrationLockDirection == "source" {
		// Keep the task-owned maintenance symlink untouched while still refreshing
		// the inactive normal configuration for a future explicit restore.
		if err := engine.ApplyOLSVHostConfigKeepDisabled(config, olsVHostConfigPath); err != nil {
			return fmt.Errorf("应用迁移中站点 OpenLiteSpeed 配置失败(site %d): %w", siteID, err)
		}
		return nil
	}

	if status == string(models.StatusPaused) || status == string(models.StatusMigrated) {
		// For paused or migrated source sites, refresh inactive config without changing the live link.
		if err := engine.ApplyOLSVHostConfigKeepDisabled(config, olsVHostConfigPath); err != nil {
			return fmt.Errorf("应用 OpenLiteSpeed 配置失败(site %d): %w", siteID, err)
		}
		return nil
	}

	if err := engine.ApplyOLSVHostConfig(config, olsVHostConfigPath, olsVHostEnabledPath(cfg, olsVHostConfigPath, domain)); err != nil {
		return fmt.Errorf("应用 OpenLiteSpeed 配置失败(site %d): %w", siteID, err)
	}
	return nil
}

// RegenerateAllSitesOLSConfigs rebuilds every site's OpenLiteSpeed virtual host config.
func RegenerateAllSitesOLSConfigs() error {
	db := database.GetDB()
	rows, err := db.Query("SELECT id FROM websites")
	if err != nil {
		log.Printf("[OpenLiteSpeed重建] 查询网站列表失败: %v", err)
		return err
	}
	defer rows.Close()

	var failures []string
	regenerated := 0
	for rows.Next() {
		var siteID int
		if err := rows.Scan(&siteID); err != nil {
			failures = append(failures, err.Error())
			continue
		}
		if err := RegenerateSiteOLSConfig(siteID); err != nil {
			log.Printf("[OpenLiteSpeed重建] 站点 %d 更新失败: %v", siteID, err)
			failures = append(failures, err.Error())
			continue
		}
		regenerated++
	}
	if err := rows.Err(); err != nil {
		failures = append(failures, err.Error())
	}
	if len(failures) > 0 {
		return fmt.Errorf("部分站点 OpenLiteSpeed 配置更新失败: %s", strings.Join(failures, "; "))
	}
	if regenerated == 0 {
		if config.AppConfig == nil {
			return errors.New("面板配置尚未初始化")
		}
		if _, err := reloadOLSManagedRegistry(config.AppConfig.Paths.OLSVHostsEnabled); err != nil {
			return fmt.Errorf("初始化 OpenLiteSpeed 默认虚拟主机失败: %w", err)
		}
	}
	log.Printf("[OpenLiteSpeed重建] 全部网站配置已更新")
	return nil
}
