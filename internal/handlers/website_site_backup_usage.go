package handlers

import (
	"context"
	"errors"
	"os"
	"path/filepath"

	"github.com/zangwp/OLS-WPanel/internal/config"
	"github.com/zangwp/OLS-WPanel/internal/executor"
	"github.com/zangwp/OLS-WPanel/internal/models"
)

var (
	listWebsiteSiteBackups        = executor.ListSiteBackups
	hasWebsiteSiteBackupArtifacts = executor.HasSiteBackupArtifacts
)

type websiteSiteBackupUsage struct {
	SiteBackupCount             int  `json:"site_backup_count"`
	SiteBackupIncompleteCount   int  `json:"site_backup_incomplete_count"`
	SiteBackupAttentionCount    int  `json:"site_backup_attention_count"`
	SiteBackupUnrecognizedCount int  `json:"site_backup_unrecognized_count"`
	SiteBackupChecked           bool `json:"site_backup_checked"`
	SiteBackupsDeleteBlocked    bool `json:"site_backups_delete_blocked"`
}

type websiteBackupUsageData struct {
	models.WebsiteBackupUsage
	websiteSiteBackupUsage
}

// Preserve the website registration while any set or unrecognized storage entry
// remains. Listing failure never means that the backup directory is empty.
func collectWebsiteSiteBackupUsage(ctx context.Context, site *models.Website) (websiteSiteBackupUsage, error) {
	var usage websiteSiteBackupUsage
	if err := ctx.Err(); err != nil {
		return usage, err
	}
	if site == nil || site.ID <= 0 || !executor.IsValidDomain(site.Domain) || config.AppConfig == nil {
		return usage, errors.New("无法确认整站备份的网站或存储路径")
	}
	root := config.AppConfig.Panel.BackupDir
	if root == "" {
		root = config.DefaultBackupDir
	}
	if !filepath.IsAbs(root) {
		return usage, errors.New("整站备份目录必须为绝对路径")
	}
	hasArtifacts, err := hasWebsiteSiteBackupArtifacts(ctx, site)
	if err != nil {
		return usage, err
	}
	points, err := listWebsiteSiteBackups(ctx, site)
	if err != nil {
		return usage, err
	}
	known := make(map[string]bool, len(points))
	for _, point := range points {
		known[point.ID] = true
		usage.SiteBackupCount++
		if point.State != "complete" || !point.LocalExists || point.RequiresAttention || point.Consistency != "controlled_quiescence" {
			usage.SiteBackupIncompleteCount++
		}
		if point.RequiresAttention {
			usage.SiteBackupAttentionCount++
		}
	}
	for _, subdir := range []string{"site-sets", "site-operations"} {
		dir := filepath.Join(root, site.Domain, subdir)
		info, err := os.Lstat(dir)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return usage, err
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return usage, errors.New("整站备份目录不是安全的真实目录")
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			return usage, err
		}
		for _, entry := range entries {
			// Recovery-operation records and their safety copies intentionally
			// remain outside the downloadable backup-point list.
			if subdir == "site-operations" || !known[entry.Name()] || !entry.IsDir() {
				usage.SiteBackupUnrecognizedCount++
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return usage, err
	}
	usage.SiteBackupChecked = true
	usage.SiteBackupsDeleteBlocked = hasArtifacts || usage.SiteBackupCount > 0 || usage.SiteBackupUnrecognizedCount > 0
	return usage, nil
}
