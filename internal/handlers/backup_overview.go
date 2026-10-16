package handlers

import (
	"log"
	"net/http"
	"os"
	"path/filepath"

	"github.com/zangwp/OLS-WPanel/internal/config"
	"github.com/zangwp/OLS-WPanel/internal/database"
	"github.com/zangwp/OLS-WPanel/internal/executor"
	"github.com/zangwp/OLS-WPanel/internal/models"

	"github.com/gin-gonic/gin"
)

// OverviewDBBackup adds current local-file availability to models.DBBackup.
// transport_status describes the last sync attempt; keep_local=0 may have removed
// the local file after a successful sync.
type OverviewDBBackup struct {
	models.DBBackup
	LocalExists bool `json:"local_exists"`
}

// OverviewFileBackup adds current local-file availability to a website file backup.
type OverviewFileBackup struct {
	models.FileBackup
	LocalExists bool `json:"local_exists"`
}

// SiteBackupOverview groups a site's database and file backups for the overview page.
type SiteBackupOverview struct {
	SiteID                int                  `json:"site_id"`
	Domain                string               `json:"domain"`
	Status                string               `json:"status"`
	SiteType              string               `json:"site_type"`
	DocumentRootSubdir    string               `json:"document_root_subdir"`
	SiteBackups           []models.SiteBackup  `json:"site_backups"`
	SiteBackupsError      string               `json:"site_backups_error,omitempty"`
	RemoteStatus          string               `json:"remote_status"`
	RemoteRebuildRequired bool                 `json:"remote_rebuild_required"`
	RemoteMessage         string               `json:"remote_message"`
	DBBackups             []OverviewDBBackup   `json:"db_backups"`
	FileBackups           []OverviewFileBackup `json:"file_backups"`
}

// GetBackupOverview lists site database/file backups and panel database backups using local state only.
// Separate backup endpoints handle downloads and deletion.
func GetBackupOverview(c *gin.Context) {
	db := database.GetDB()
	cfg := config.AppConfig

	sites := []SiteBackupOverview{}
	siteIndex := map[int]int{}
	siteBindings := map[int]*models.Website{}

	rows, err := db.Query(`SELECT id,domain,status,site_type,document_root_subdir,web_root,db_name,db_user,system_user FROM websites ORDER BY domain`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("查询网站列表失败"))
		return
	}
	for rows.Next() {
		var id int
		var domain, status, siteType, documentRoot, webRoot, dbName, dbUser, systemUser string
		if err := rows.Scan(&id, &domain, &status, &siteType, &documentRoot, &webRoot, &dbName, &dbUser, &systemUser); err != nil {
			log.Printf("备份总览: 扫描网站列表行失败: %v", err)
			rows.Close()
			c.JSON(http.StatusInternalServerError, models.ErrorResponse("读取网站列表失败"))
			return
		}
		siteIndex[id] = len(sites)
		siteBindings[id] = &models.Website{ID: id, Domain: domain, Status: models.WebsiteStatus(status), SiteType: siteType,
			DocumentRootSubdir: documentRoot, WebRoot: webRoot, DBName: dbName, DBUser: dbUser, SystemUser: systemUser}
		sites = append(sites, SiteBackupOverview{
			SiteID:             id,
			Domain:             domain,
			Status:             status,
			SiteType:           siteType,
			DocumentRootSubdir: documentRoot,
			SiteBackups:        []models.SiteBackup{},
			RemoteStatus:       "unknown",
			DBBackups:          []OverviewDBBackup{},
			FileBackups:        []OverviewFileBackup{},
		})
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("读取网站列表失败"))
		return
	}
	rows.Close()
	stateRows, err := db.Query(`SELECT site_id,status,rebuild_required,message FROM remote_backup_site_state`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("查询远程备份维护状态失败"))
		return
	}
	for stateRows.Next() {
		var siteID, rebuild int
		var status, message string
		if err := stateRows.Scan(&siteID, &status, &rebuild, &message); err != nil {
			log.Printf("备份总览: 扫描远程维护状态失败: %v", err)
			stateRows.Close()
			c.JSON(http.StatusInternalServerError, models.ErrorResponse("读取远程备份维护状态失败"))
			return
		}
		if idx, ok := siteIndex[siteID]; ok {
			sites[idx].RemoteStatus = status
			sites[idx].RemoteRebuildRequired = rebuild == 1
			sites[idx].RemoteMessage = message
		}
	}
	if err := stateRows.Err(); err != nil {
		stateRows.Close()
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("读取远程备份维护状态失败"))
		return
	}
	stateRows.Close()

	dbRows, err := db.Query(`SELECT id, site_id, filename, file_size, db_name, auto, transport_status, transport_message, created_at
		FROM db_backups ORDER BY created_at DESC`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("查询数据库备份列表失败"))
		return
	}
	for dbRows.Next() {
		var b OverviewDBBackup
		var auto int
		if err := dbRows.Scan(&b.ID, &b.SiteID, &b.Filename, &b.FileSize, &b.DBName, &auto,
			&b.TransportStatus, &b.TransportMessage, &b.CreatedAt); err != nil {
			log.Printf("备份总览: 扫描数据库备份行失败: %v", err)
			dbRows.Close()
			c.JSON(http.StatusInternalServerError, models.ErrorResponse("读取数据库备份列表失败"))
			return
		}
		b.Auto = auto == 1
		if idx, ok := siteIndex[b.SiteID]; ok {
			localPath := filepath.Join(cfg.Panel.BackupDir, sites[idx].Domain, "db", b.Filename)
			b.LocalExists = localFileExists(localPath)
			sites[idx].DBBackups = append(sites[idx].DBBackups, b)
		}
	}
	if err := dbRows.Err(); err != nil {
		dbRows.Close()
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("读取数据库备份列表失败"))
		return
	}
	dbRows.Close()

	fileRows, err := db.Query(`SELECT id, site_id, filename, file_size, mode, transport_status, transport_message, created_at
		FROM file_backups ORDER BY created_at DESC`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("查询文件备份列表失败"))
		return
	}
	for fileRows.Next() {
		var b OverviewFileBackup
		if err := fileRows.Scan(&b.ID, &b.SiteID, &b.Filename, &b.FileSize, &b.Mode,
			&b.TransportStatus, &b.TransportMessage, &b.CreatedAt); err != nil {
			log.Printf("备份总览: 扫描文件备份行失败: %v", err)
			fileRows.Close()
			c.JSON(http.StatusInternalServerError, models.ErrorResponse("读取文件备份列表失败"))
			return
		}
		if idx, ok := siteIndex[b.SiteID]; ok {
			b.LocalExists = fileBackupLocalExists(sites[idx].Domain, b.Filename)
			sites[idx].FileBackups = append(sites[idx].FileBackups, b)
		}
	}
	if err := fileRows.Err(); err != nil {
		fileRows.Close()
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("读取文件备份列表失败"))
		return
	}
	fileRows.Close()
	// Old independent records are never inferred to be one recovery point.
	// Complete points are recorded by the coordinated executor in private
	// manifests, independently from the ordinary backup rotation policies.
	for i := range sites {
		points, err := listSiteBackupSets(c.Request.Context(), siteBindings[sites[i].SiteID])
		if err != nil {
			log.Printf("备份总览: 网站 %d 整站备份清单读取失败: %v", sites[i].SiteID, err)
			sites[i].SiteBackupsError = "整站备份清单未能完整读取，请检查备份目录和维护状态"
		}
		if points != nil {
			sites[i].SiteBackups = points
		}
	}

	panelBackupDir := filepath.Join(cfg.Panel.BackupDir, "panel-db")
	panelBackups, err := database.ListDBBackups(panelBackupDir)
	if err != nil {
		log.Printf("备份总览: 读取面板数据库备份列表失败: %v", err)
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("读取面板数据库备份列表失败"))
		return
	}

	c.JSON(http.StatusOK, models.SuccessResponse(gin.H{
		"sites":            sites,
		"panel_db_backups": panelBackups,
	}))
}

// ReconcileBackupStatus explicitly reconciles local/synced records with the current
// remote destination and uploads missing remote files still available locally.
// Keep network access out of GetBackupOverview. Full archive rebuilds run only
// in the daily background job; HTTP requests must not trigger compression.
func ReconcileBackupStatus(c *gin.Context) {
	updated, err := executor.MaintainRemoteBackups(false)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse(err.Error()))
		return
	}
	c.JSON(http.StatusOK, models.SuccessResponse(gin.H{"updated": updated}))
}

// localFileExists uses only local stat. Only os.IsNotExist means missing;
// treat permission and I/O errors as present to avoid false missing-file reports.
func localFileExists(path string) bool {
	_, err := os.Stat(path)
	if err == nil {
		return true
	}
	if os.IsNotExist(err) {
		return false
	}
	log.Printf("备份总览: 检查本地文件状态失败 %s: %v", path, err)
	return true
}

// fileBackupLocalExists checks the fixed config.DefaultBackupDir used by file backup
// creation and remote sync. Using Panel.BackupDir could report existing files as missing.
func fileBackupLocalExists(domain, filename string) bool {
	return fileBackupLocalExistsFromRoot(config.DefaultBackupDir, domain, filename)
}

// fileBackupLocalExistsFromRoot accepts a root for tests; production uses config.DefaultBackupDir.
func fileBackupLocalExistsFromRoot(root, domain, filename string) bool {
	return localFileExists(filepath.Join(root, domain, "files", filename))
}
