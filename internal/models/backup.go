package models

import "time"

type DBBackup struct {
	ID               int       `json:"id"`
	SiteID           int       `json:"site_id"`
	Filename         string    `json:"filename"`
	FileSize         int64     `json:"file_size"`
	DBName           string    `json:"db_name"`
	Auto             bool      `json:"auto"`
	TransportStatus  string    `json:"transport_status"`
	TransportMessage string    `json:"transport_message"`
	CreatedAt        time.Time `json:"created_at"`
}

type BackupSettings struct {
	Enabled   bool `json:"enabled"`
	KeepCount int  `json:"keep_count"`
}

type FileBackup struct {
	ID               int       `json:"id"`
	SiteID           int       `json:"site_id"`
	Filename         string    `json:"filename"`
	FileSize         int64     `json:"file_size"`
	Mode             string    `json:"mode"`
	TransportStatus  string    `json:"transport_status"`
	TransportMessage string    `json:"transport_message"`
	CreatedAt        time.Time `json:"created_at"`
}

// SiteBackup describes one independently retained, paired website backup.
// Complete means both artifacts were verified under controlled quiescence;
// it never means a transaction spanning MariaDB and the filesystem.
type SiteBackup struct {
	ID                string    `json:"id"`
	SiteID            int       `json:"site_id"`
	CreatedAt         time.Time `json:"created_at"`
	State             string    `json:"state"`
	LocalExists       bool      `json:"local_exists"`
	FileSize          int64     `json:"file_size"`
	DBSize            int64     `json:"db_size"`
	Message           string    `json:"message"`
	RequiresAttention bool      `json:"requires_attention"`
	Consistency       string    `json:"consistency"`
}

type SiteBackupArtifact struct {
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type SiteBackupManifest struct {
	Version int `json:"version"`
	SiteBackup
	Domain                 string             `json:"domain"`
	Aliases                string             `json:"aliases"`
	WebRoot                string             `json:"web_root"`
	SystemUser             string             `json:"system_user"`
	DBName                 string             `json:"db_name"`
	DBUser                 string             `json:"db_user"`
	TablePrefix            string             `json:"table_prefix"`
	Files                  SiteBackupArtifact `json:"files"`
	Database               SiteBackupArtifact `json:"database"`
	Atomic                 bool               `json:"atomic"`
	Phase                  string             `json:"phase"`
	Operation              string             `json:"operation"`
	SafetyFiles            string             `json:"safety_files,omitempty"`
	SafetyDatabase         string             `json:"safety_database,omitempty"`
	OriginalVHost          string             `json:"original_vhost,omitempty"`
	VHostPath              string             `json:"vhost_path,omitempty"`
	MaintenanceRoot        string             `json:"maintenance_root,omitempty"`
	Marker                 string             `json:"marker,omitempty"`
	DBAccountLocked        bool               `json:"db_account_locked"`
	ReadOnlyMount          bool               `json:"read_only_mount"`
	MountID                int                `json:"mount_id"`
	MaintenanceVHostSHA256 string             `json:"maintenance_vhost_sha256,omitempty"`
	UpdatedAt              time.Time          `json:"updated_at"`
}

// BackupCronJobRef summarizes an associated job for the site-deletion warning.
type BackupCronJobRef struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}

// WebsiteBackupUsage summarizes a site's backup data for the site-deletion warning.
type WebsiteBackupUsage struct {
	DBBackupCount     int                `json:"db_backup_count"`
	FileBackupCount   int                `json:"file_backup_count"`
	AutoBackupEnabled bool               `json:"auto_backup_enabled"`
	CronJobs          []BackupCronJobRef `json:"cron_jobs"`
}

// HasBackupData reports whether backup data or settings need administrator attention.
func (u WebsiteBackupUsage) HasBackupData() bool {
	return u.DBBackupCount > 0 || u.FileBackupCount > 0 || u.AutoBackupEnabled || len(u.CronJobs) > 0
}
