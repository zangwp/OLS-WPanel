package executor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/zangwp/OLS-WPanel/internal/config"
	"github.com/zangwp/OLS-WPanel/internal/models"
)

const siteBackupManifestVersion = 1

func validSiteBackupID(id string) bool {
	parsed, err := uuid.Parse(id)
	return err == nil && parsed.String() == id && parsed != uuid.Nil
}

func siteBackupRoot(site *models.Website) (string, error) {
	if site == nil || site.ID <= 0 || !IsValidDomain(site.Domain) || config.AppConfig == nil {
		return "", errors.New("整站备份的网站或路径配置无效")
	}
	root := config.AppConfig.Panel.BackupDir
	if root == "" {
		root = backupsRoot
	}
	if !filepath.IsAbs(root) {
		return "", errors.New("备份目录必须为绝对路径")
	}
	return filepath.Join(root, site.Domain, "site-sets"), nil
}

func siteBackupDirectory(site *models.Website, id string) (string, error) {
	if !validSiteBackupID(id) {
		return "", errors.New("整站备份 ID 无效")
	}
	root, err := siteBackupRoot(site)
	if err != nil {
		return "", err
	}
	return filepath.Join(root, id), nil
}

// HasSiteBackupArtifacts also sees incomplete, unknown and recovery-operation
// records. Lifecycle workers call it while holding the site's operation slot;
// a handler's earlier list/count is not sufficient to prevent queue races.
func HasSiteBackupArtifacts(ctx context.Context, site *models.Website) (bool, error) {
	root, err := siteBackupRoot(site)
	if err != nil {
		return false, err
	}
	for _, dir := range []string{root, filepath.Join(filepath.Dir(root), "site-operations")} {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		info, err := os.Lstat(dir)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return false, err
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return false, errors.New("整站备份目录不是安全的真实目录")
		}
		if err = verifySiteBackupParentDirectories(dir); err != nil {
			return false, err
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			return false, err
		}
		if len(entries) != 0 {
			return true, nil
		}
	}
	return false, nil
}

func verifySiteBackupParentDirectories(dir string) error {
	if err := fileRestoreNoSymlinkDirectories(dir); err != nil {
		return err
	}
	for current := dir; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil {
			return err
		}
		uid, _, known := wpInventoryFileOwner(info)
		if !known || uid != 0 || info.Mode().Perm()&0022 != 0 {
			return errors.New("整站备份路径必须由 root 管理且普通用户不可改名")
		}
		if current == filepath.Dir(current) {
			break
		}
	}
	return nil
}

type siteBackupMaintenanceOwner struct {
	Version   int    `json:"version"`
	SiteID    int    `json:"site_id"`
	ID        string `json:"id"`
	Operation string `json:"operation"`
	Marker    string `json:"marker"`
}

func writeSiteBackupMaintenanceOwner(site *models.Website, manifest *models.SiteBackupManifest) error {
	root, err := siteBackupRoot(site)
	if err != nil {
		return err
	}
	parent := filepath.Dir(root)
	if err = verifySiteBackupParentDirectories(parent); err != nil {
		return err
	}
	data, err := json.Marshal(siteBackupMaintenanceOwner{siteBackupManifestVersion, site.ID, manifest.ID, manifest.Operation, manifest.Marker})
	if err != nil {
		return err
	}
	if err = atomicWriteMigrationFile(filepath.Join(parent, "maintenance-owner.json"), data, 0600); err != nil {
		return err
	}
	return syncDirectory(parent)
}

func readSiteBackupMaintenanceOwner(ctx context.Context, site *models.Website) (*models.SiteBackupManifest, string, error) {
	root, err := siteBackupRoot(site)
	if err != nil {
		return nil, "", err
	}
	parent := filepath.Dir(root)
	if err = verifySiteBackupParentDirectories(parent); err != nil {
		return nil, "", err
	}
	filePath := filepath.Join(parent, "maintenance-owner.json")
	info, err := os.Lstat(filePath)
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 4096 {
		return nil, "", errors.New("本轮维护归属指针缺失或不安全；不会使用旧日志解除维护")
	}
	file, err := os.Open(filePath)
	if err != nil {
		return nil, "", err
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil || !os.SameFile(info, after) {
		return nil, "", errors.New("维护归属指针身份变化")
	}
	var owner siteBackupMaintenanceOwner
	if err = json.NewDecoder(io.LimitReader(file, 4096)).Decode(&owner); err != nil {
		return nil, "", err
	}
	if owner.Version != siteBackupManifestVersion || owner.SiteID != site.ID || !validSiteBackupID(owner.ID) || !validSiteBackupID(owner.Marker) || (owner.Operation != "create" && owner.Operation != "restore") {
		return nil, "", errors.New("维护归属指针不属于本轮受管操作")
	}
	if owner.Operation == "restore" {
		root = filepath.Join(parent, "site-operations")
	}
	dir := filepath.Join(root, owner.ID)
	if err = verifySiteBackupParentDirectories(dir); err != nil {
		return nil, "", err
	}
	if err = verifyFileRestorePrivateDirectory(dir); err != nil {
		return nil, "", err
	}
	path := filepath.Join(dir, "manifest.json")
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Size() <= 0 || before.Size() > 1<<20 {
		return nil, "", errors.New("本轮维护日志损坏，不会回退到旧日志")
	}
	input, err := os.Open(path)
	if err != nil {
		return nil, "", err
	}
	defer input.Close()
	opened, err := input.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return nil, "", errors.New("维护日志身份变化")
	}
	var manifest models.SiteBackupManifest
	if err = decodeSiteBackupRecoveryManifest(input, &manifest); err != nil {
		return nil, "", err
	}
	if manifest.ID != owner.ID || manifest.Operation != owner.Operation || manifest.Marker != owner.Marker || manifest.SiteID != site.ID || manifest.Domain != site.Domain || manifest.WebRoot != site.WebRoot || manifest.DBName != site.DBName || manifest.DBUser != site.DBUser || manifest.TablePrefix != site.TablePrefix || manifest.SystemUser != site.SystemUser || manifest.Aliases != site.Aliases {
		return nil, "", errors.New("维护日志和当前站点归属不一致")
	}
	return &manifest, dir, ctx.Err()
}

func writeSiteBackupManifest(dir string, manifest *models.SiteBackupManifest) error {
	if manifest == nil || manifest.Version != siteBackupManifestVersion || !validSiteBackupID(manifest.ID) || filepath.Base(dir) != manifest.ID {
		return errors.New("整站备份清单无效")
	}
	manifest.UpdatedAt = time.Now().UTC()
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	if len(data) > 1<<20 {
		return errors.New("整站备份清单过大")
	}
	if err = atomicWriteMigrationFile(filepath.Join(dir, "manifest.json"), data, 0600); err != nil {
		return err
	}
	return syncDirectory(dir)
}

func readSiteBackupManifest(ctx context.Context, site *models.Website, id string) (*models.SiteBackupManifest, string, error) {
	if err := ctx.Err(); err != nil {
		return nil, "", err
	}
	dir, err := siteBackupDirectory(site, id)
	if err != nil {
		return nil, "", err
	}
	if err = verifySiteBackupParentDirectories(dir); err != nil {
		return nil, "", err
	}
	if err = verifyFileRestorePrivateDirectory(dir); err != nil {
		return nil, "", err
	}
	path := filepath.Join(dir, "manifest.json")
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Size() <= 0 || before.Size() > 1<<20 {
		return nil, "", errors.New("整站备份清单缺失或不安全")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, "", err
	}
	defer f.Close()
	after, err := f.Stat()
	if err != nil || !os.SameFile(before, after) {
		return nil, "", errors.New("整站备份清单身份变化")
	}
	var manifest models.SiteBackupManifest
	if err = json.NewDecoder(io.LimitReader(f, 1<<20)).Decode(&manifest); err != nil {
		return nil, "", err
	}
	if manifest.Version != siteBackupManifestVersion || manifest.ID != id || manifest.SiteID != site.ID || manifest.Domain != site.Domain || manifest.Atomic {
		return nil, "", errors.New("整站备份不属于当前网站或清单版本不受支持")
	}
	return &manifest, dir, nil
}

func ListSiteBackups(ctx context.Context, site *models.Website) ([]models.SiteBackup, error) {
	root, err := siteBackupRoot(site)
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(root)
	if os.IsNotExist(err) {
		return []models.SiteBackup{}, nil
	}
	if err != nil {
		return nil, err
	}
	if err = verifySiteBackupParentDirectories(root); err != nil {
		return nil, err
	}
	if len(entries) > 10000 {
		return nil, errors.New("整站备份集合过多，请先整理磁盘")
	}
	backups := make([]models.SiteBackup, 0, len(entries))
	for _, entry := range entries {
		if !validSiteBackupID(entry.Name()) || !entry.IsDir() {
			continue
		}
		manifest, dir, readErr := readSiteBackupManifest(ctx, site, entry.Name())
		if readErr != nil {
			if err = ctx.Err(); err != nil {
				return nil, err
			}
			backups = append(backups, models.SiteBackup{ID: entry.Name(), SiteID: site.ID, State: "incomplete", Message: "清单不可用，不能恢复；可查看磁盘后删除"})
			continue
		}
		item := manifest.SiteBackup
		item.FileSize, item.DBSize = manifest.Files.Size, manifest.Database.Size
		item.LocalExists = validSiteBackupArtifact(dir, manifest.Files, "files.tar.gz", false) == nil && validSiteBackupArtifact(dir, manifest.Database, "database.sql.gz", false) == nil
		backups = append(backups, item)
	}
	sort.Slice(backups, func(i, j int) bool { return backups[i].CreatedAt.After(backups[j].CreatedAt) })
	return backups, nil
}

func validSiteBackupArtifact(dir string, artifact models.SiteBackupArtifact, expected string, hash bool) error {
	if artifact.Name != expected || artifact.Size <= 0 || artifact.Size > fileRestoreMaxBytes || len(artifact.SHA256) != 64 {
		return errors.New("备份组件尚未完整验证")
	}
	if _, err := hex.DecodeString(artifact.SHA256); err != nil {
		return errors.New("备份组件指纹无效")
	}
	file, err := openFileRestoreArchive(filepath.Join(dir, expected), artifact.Size)
	if err != nil {
		return errors.New("本地备份组件缺失或已变化")
	}
	defer file.Close()
	if hash {
		hasher := sha256.New()
		if _, err = io.Copy(hasher, file); err != nil {
			return err
		}
		if hex.EncodeToString(hasher.Sum(nil)) != artifact.SHA256 {
			return errors.New("备份组件 SHA-256 不匹配，未执行恢复")
		}
	}
	return nil
}

func hashSiteBackupArtifact(ctx context.Context, path, name string) (models.SiteBackupArtifact, error) {
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Size() <= 0 {
		return models.SiteBackupArtifact{}, errors.New("备份组件为空或不安全")
	}
	file, err := openFileRestoreArchive(path, before.Size())
	if err != nil {
		return models.SiteBackupArtifact{}, err
	}
	defer file.Close()
	hasher := sha256.New()
	buffer := make([]byte, 128<<10)
	for {
		if err = ctx.Err(); err != nil {
			return models.SiteBackupArtifact{}, err
		}
		n, readErr := file.Read(buffer)
		if n > 0 {
			_, _ = hasher.Write(buffer[:n])
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return models.SiteBackupArtifact{}, readErr
		}
	}
	if err = file.Sync(); err != nil {
		return models.SiteBackupArtifact{}, err
	}
	return models.SiteBackupArtifact{Name: name, Size: before.Size(), SHA256: hex.EncodeToString(hasher.Sum(nil))}, nil
}

func ValidateSiteBackupRestore(ctx context.Context, site *models.Website, id string) error {
	manifest, dir, err := readSiteBackupManifest(ctx, site, id)
	if err != nil {
		return err
	}
	if manifest.State != "complete" || manifest.RequiresAttention || manifest.Consistency != "controlled_quiescence" {
		return errors.New("只有已完整验证且无需处理现场的整站备份可以恢复")
	}
	if manifest.WebRoot != site.WebRoot || manifest.SystemUser != site.SystemUser || manifest.DBName != site.DBName || manifest.DBUser != site.DBUser || manifest.TablePrefix != site.TablePrefix {
		return errors.New("当前站点目录、数据库或表前缀与备份绑定不一致；不支持迁移式恢复")
	}
	if err = validSiteBackupArtifact(dir, manifest.Files, "files.tar.gz", false); err != nil {
		return err
	}
	return validSiteBackupArtifact(dir, manifest.Database, "database.sql.gz", false)
}

func GetSiteBackupArtifact(ctx context.Context, site *models.Website, id, component string) (string, string, error) {
	manifest, dir, err := readSiteBackupManifest(ctx, site, id)
	if err != nil {
		return "", "", err
	}
	var artifact models.SiteBackupArtifact
	var expected string
	switch component {
	case "files":
		artifact = manifest.Files
		expected = "files.tar.gz"
	case "database":
		artifact = manifest.Database
		expected = "database.sql.gz"
	default:
		return "", "", errors.New("备份组件只能是 files 或 database")
	}
	if err = validSiteBackupArtifact(dir, artifact, expected, false); err != nil {
		return "", "", err
	}
	return filepath.Join(dir, artifact.Name), site.Domain + "_" + id + "_" + artifact.Name, nil
}

func DeleteSiteBackup(ctx context.Context, site *models.Website, id string) error {
	lock, err := AcquireFileBackupOperationLock(ctx)
	if err != nil {
		return err
	}
	defer lock.Close()
	if !TryAcquireSiteOpLock(site.ID, "delete_site_backup") {
		return errors.New("网站正在操作或维护中，不能删除整站备份")
	}
	defer ReleaseSiteOpLock(site.ID)
	var status string
	if err = databaseStatusForSite(ctx, site.ID, &status); err != nil {
		return err
	}
	if status == string(models.StatusBackupMaintenance) {
		return errors.New("网站仍在整站备份维护状态，请先处理恢复现场")
	}
	dir, err := siteBackupDirectory(site, id)
	if err != nil {
		return err
	}
	if err = verifySiteBackupParentDirectories(dir); err != nil {
		return err
	}
	if err = verifyFileRestorePrivateDirectory(dir); err != nil {
		return err
	}
	manifest, _, readErr := readSiteBackupManifest(ctx, site, id)
	if readErr == nil && manifest.RequiresAttention {
		return errors.New("该集合仍记录待处理的恢复现场，不能自动删除安全副本")
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	// The validated UUID directory is independent of ordinary backup rotation.
	if err = os.RemoveAll(dir); err != nil {
		return fmt.Errorf("删除整站备份失败: %w", err)
	}
	return syncDirectory(filepath.Dir(dir))
}

func siteBackupArtifactExcludes() []string {
	return []string{"--exclude=*/.lscache", "--exclude=*/wp-content/cache", "--exclude=*/wp-content/litespeed", "--exclude=*/wp-content/upgrade", "--exclude=*/.maintenance"}
}

func safeSiteBackupMessage(err error) string {
	if err == nil {
		return ""
	}
	message := strings.TrimSpace(err.Error())
	if len(message) > 2048 {
		message = message[:2048]
	}
	return message
}
