package executor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"time"

	"github.com/zangwp/OLS-WPanel/internal/config"
	"github.com/zangwp/OLS-WPanel/internal/database"
	"github.com/zangwp/OLS-WPanel/internal/models"
)

var ErrWebsiteSecurityVerificationSave = errors.New("security verification result could not be saved")

type websiteSecurityFingerprintFile struct {
	digest string
	ok     bool
}

type websiteSecurityFingerprintReader struct {
	site  *models.Website
	files map[string]websiteSecurityFingerprintFile
}

func newWebsiteSecurityFingerprintReader(site *models.Website) *websiteSecurityFingerprintReader {
	return &websiteSecurityFingerprintReader{site: site, files: make(map[string]websiteSecurityFingerprintFile)}
}

// Content and permissions matter; an identical rewrite, unrelated row update or
// file timestamp change alone must not erase an earlier diagnostic observation.
func (r *websiteSecurityFingerprintReader) file(root, path string, limit int64, optional bool) (string, bool) {
	if path == "" && optional {
		return "absent", true
	}
	cacheKey := root + "\x00" + path
	if cached, ok := r.files[cacheKey]; ok {
		return cached.digest, cached.ok
	}
	data, err := readSiteSecurityFile(root, path, limit)
	if optional && os.IsNotExist(err) {
		r.files[cacheKey] = websiteSecurityFingerprintFile{"absent", true}
		return "absent", true
	}
	if err != nil {
		r.files[cacheKey] = websiteSecurityFingerprintFile{}
		return "", false
	}
	info, err := os.Lstat(path)
	if err != nil {
		return "", false
	}
	uid, gid, known := wpInventoryFileOwner(info)
	h := sha256.New()
	h.Write(data)
	fmt.Fprintf(h, "|%s|%d|%d|%t", info.Mode(), uid, gid, known)
	digest := hex.EncodeToString(h.Sum(nil))
	r.files[cacheKey] = websiteSecurityFingerprintFile{digest, true}
	return digest, true
}

func websiteSecurityRuntimeIdentity(path string) string {
	info, err := os.Stat(path)
	if err != nil {
		return "unavailable:" + path
	}
	uid, gid, known := wpInventoryFileOwner(info)
	real, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "unavailable:" + path
	}
	return fmt.Sprintf("%s|%d|%d|%s|%d|%d|%t", real, info.Size(), info.ModTime().UnixNano(), info.Mode(), uid, gid, known)
}

func (r *websiteSecurityFingerprintReader) check(key string) (string, bool) {
	site, cfg := r.site, config.AppConfig
	if site == nil || cfg == nil || !WebsiteSecurityCheckVerifiable(key) {
		return "", false
	}
	inputs := map[string]any{"version": 2, "key": key, "site_id": site.ID, "domain": site.Domain, "site_type": site.SiteType, "status": site.Status}
	addFile := func(name, root, path string, limit int64, optional bool) bool {
		digest, ok := r.file(root, path, limit, optional)
		inputs[name], inputs[name+"_path"] = digest, path
		return ok
	}
	core := key == "application_passwords" || key == "file_editing" || key == "debug_display" || key == "wp_updates" || key == "login_protection"
	if core {
		inputs["web_root"], inputs["document_root_subdir"], inputs["system_user"] = site.WebRoot, site.DocumentRootSubdir, site.SystemUser
		inputs["account_identity"] = "unavailable"
		if account, err := user.Lookup(site.SystemUser); err == nil {
			inputs["account_identity"] = account.Uid + ":" + account.Gid + ":" + account.HomeDir
		}
		inputs["php_version"], inputs["core_checker"] = site.PHPVersion, siteSecurityCorePHP
		php := LSPHPBinaryPath()
		if site.PHPVersion != "" {
			runtime, err := ResolveLSPHPRuntime(site.PHPVersion, false)
			if err != nil {
				return "", false
			}
			php = runtime.CLIBinary
		}
		inputs["php_runtime"] = websiteSecurityRuntimeIdentity(php)
		inputs["file_lock_enabled"], inputs["file_lock_mode"], inputs["file_lock_apply_status"] = site.FileLockEnabled, site.FileLockMode, site.FileLockApplyStatus
		rootInfo, err := os.Lstat(site.WebRoot)
		if err != nil || !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
			return "", false
		}
		uid, gid, known := wpInventoryFileOwner(rootInfo)
		inputs["root_permissions"] = fmt.Sprintf("%s|%d|%d|%t", rootInfo.Mode(), uid, gid, known)
		if !addFile("wp_config", cfg.Paths.WWWRoot, filepath.Join(site.WebRoot, "wp-config.php"), 1024*1024, false) {
			return "", false
		}
		for _, name := range []string{"wp-load.php", "wp-settings.php", "wp-includes/version.php"} {
			if !addFile(name, cfg.Paths.WWWRoot, filepath.Join(site.WebRoot, filepath.FromSlash(name)), 1024*1024, true) {
				return "", false
			}
		}
	}
	if key == "https" || key == "login_protection" || key == "sql_injection" || key == "sensitive_files" || key == "uploads_php" || key == "xmlrpc" {
		if !addFile("vhost", cfg.Paths.OLSVHostsAvailable, site.OLSVHostConfigPath, 256*1024, false) {
			return "", false
		}
	}
	switch key {
	case "https":
		inputs["ssl_enabled"] = site.SSLEnabled
		if !addFile("certificate", cfg.Paths.Certificates, site.SSLCertPath, 128*1024, false) || !addFile("certificate_key", cfg.Paths.Certificates, site.SSLKeyPath, 128*1024, false) {
			return "", false
		}
	case "sql_injection":
		block, ban := GetSQLiProtectionSettings()
		inputs["block"], inputs["ban"] = block, ban
	case "xmlrpc":
		inputs["xmlrpc_enabled"] = site.XMLRPCEnabled
	case "application_passwords":
		inputs["disabled"] = site.DisableApplicationPasswords
	case "file_editing":
		inputs["disabled"] = site.DisableFileEditing
	case "wp_updates":
		inputs["disabled"] = site.DisableWPUpdates
	}
	encoded, err := json.Marshal(inputs)
	if err != nil {
		return "", false
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), true
}

func websiteSecurityFingerprint(site *models.Website, key string) (string, bool) {
	return newWebsiteSecurityFingerprintReader(site).check(key)
}

func websiteSecuritySavedVerification(record database.SiteSecurityVerificationRecord, reader *websiteSecurityFingerprintReader) *models.WebsiteSecurityVerification {
	verification := &models.WebsiteSecurityVerification{State: record.State, CheckedAt: record.CheckedAt, ReasonCode: record.ReasonCode, Source: record.Source, Status: "unavailable"}
	if current, ok := reader.check(record.Key); ok {
		verification.Status = "changed"
		if current == record.Fingerprint {
			verification.Status = "unchanged"
		}
	}
	if record.ValidUntil != "" {
		until, err := time.Parse(time.RFC3339Nano, record.ValidUntil)
		if err != nil {
			verification.Status = "unavailable"
		} else if !time.Now().Before(until) && verification.Status != "unavailable" {
			verification.Status = "changed"
		}
	}
	return verification
}

func applySavedWebsiteSecurityVerification(ctx context.Context, site *models.Website, report *models.WebsiteSecurityStatus) {
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	records, err := database.LoadSiteSecurityVerifications(ctx, database.GetDB(), site.ID)
	if err != nil {
		report.VerificationUnavailable = true
		return
	}
	reader := newWebsiteSecurityFingerprintReader(site)
	for i := range report.Checks {
		if record, exists := records[report.Checks[i].Key]; exists {
			report.Checks[i].Verification = websiteSecuritySavedVerification(record, reader)
		}
	}
}

func rememberWebsiteSecurityVerification(ctx context.Context, site *models.Website, check *models.WebsiteSecurityCheck, expected string) error {
	record := database.SiteSecurityVerificationRecord{SiteID: site.ID, Key: check.Key, State: check.State, CheckedAt: time.Now().UTC().Format(time.RFC3339Nano), ReasonCode: check.ReasonCode, Source: check.EvidenceSource, Fingerprint: expected}
	if check.Key == "https" && check.State == "effective" {
		until, err := time.Parse(time.RFC3339, check.Details["expires_at"])
		if err != nil || !time.Now().Before(until) {
			return ErrWebsiteSecurityVerificationSave
		}
		record.ValidUntil = until.UTC().Format(time.RFC3339)
	}
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	if err := database.SaveSiteSecurityVerification(ctx, database.GetDB(), record); err != nil {
		return errors.Join(ErrWebsiteSecurityVerificationSave, err)
	}
	check.Verification = websiteSecuritySavedVerification(record, newWebsiteSecurityFingerprintReader(site))
	return nil
}
