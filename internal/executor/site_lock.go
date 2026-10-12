package executor

import (
	"sync"

	"github.com/zangwp/OLS-WPanel/internal/database"
)

var (
	wpSiteOpMu               sync.Mutex
	wpSiteOpBusy             = map[int]string{}
	wpSiteOpLifecycleRelease = map[int]func(){}
	wpSiteOpOwners           = map[int]*siteOperationOwner{}
)

// TryAcquireSiteOpLock claims an exclusive "site busy" slot so a manual
// update-backup database restore and a WordPress core/plugin/theme update
// cannot run against the same site at the same time. The caller must call
// ReleaseSiteOpLock once the operation finishes (success or failure).
func TryAcquireSiteOpLock(siteID int, reason string) bool {
	release, err := panelOperations.acquire()
	if err != nil {
		return false
	}
	claimed := false
	defer func() {
		if !claimed {
			release()
		}
	}()
	wpSiteOpMu.Lock()
	defer wpSiteOpMu.Unlock()
	if _, busy := wpSiteOpBusy[siteID]; busy {
		return false
	}
	if siteBackupMaintenanceBlocksSiteOp(siteID) {
		return false
	}
	if db := database.GetDB(); db != nil {
		active, err := database.MaintenanceWindowActive(db, siteID)
		if err != nil || active {
			return false
		}
	}
	wpSiteOpBusy[siteID] = reason
	wpSiteOpOwners[siteID] = &siteOperationOwner{marker: 1}
	wpSiteOpLifecycleRelease[siteID] = release
	claimed = true
	return true
}

// TryAcquireCompanionDeployLock reserves the in-process site slot without
// treating a persisted maintenance window as a blocker. OLS WPanel owns the
// companion plugin and may replace it while AI access or temporary maintenance
// is active; real in-process writers remain mutually exclusive.
func TryAcquireCompanionDeployLock(siteID int) bool {
	release, err := panelOperations.acquire()
	if err != nil {
		return false
	}
	claimed := false
	defer func() {
		if !claimed {
			release()
		}
	}()
	wpSiteOpMu.Lock()
	defer wpSiteOpMu.Unlock()
	if _, busy := wpSiteOpBusy[siteID]; busy {
		return false
	}
	if siteBackupMaintenanceBlocksSiteOp(siteID) {
		return false
	}
	wpSiteOpBusy[siteID] = "companion_upgrade"
	wpSiteOpOwners[siteID] = &siteOperationOwner{marker: 1}
	wpSiteOpLifecycleRelease[siteID] = release
	claimed = true
	return true
}

// TryAcquireSiteFileOpLock serializes a long file operation with other site
// mutations while allowing an already-authorized maintenance window to remain
// active. File operations perform their own path-level maintenance checks.
func TryAcquireSiteFileOpLock(siteID int, reason string) bool {
	release, err := panelOperations.acquire()
	if err != nil {
		return false
	}
	claimed := false
	defer func() {
		if !claimed {
			release()
		}
	}()
	wpSiteOpMu.Lock()
	defer wpSiteOpMu.Unlock()
	if _, busy := wpSiteOpBusy[siteID]; busy {
		return false
	}
	if siteBackupMaintenanceBlocksSiteOp(siteID) {
		return false
	}
	wpSiteOpBusy[siteID] = reason
	wpSiteOpOwners[siteID] = &siteOperationOwner{marker: 1}
	wpSiteOpLifecycleRelease[siteID] = release
	claimed = true
	return true
}

// Only the maintenance executor can enter its own persisted window.
func tryAcquireMaintenanceOp(siteID int) bool {
	release, err := panelOperations.acquire()
	if err != nil {
		return false
	}
	claimed := false
	defer func() {
		if !claimed {
			release()
		}
	}()
	wpSiteOpMu.Lock()
	defer wpSiteOpMu.Unlock()
	if _, busy := wpSiteOpBusy[siteID]; busy {
		return false
	}
	if siteBackupMaintenanceBlocksSiteOp(siteID) {
		return false
	}
	wpSiteOpBusy[siteID] = "maintenance"
	wpSiteOpOwners[siteID] = &siteOperationOwner{marker: 1}
	wpSiteOpLifecycleRelease[siteID] = release
	claimed = true
	return true
}

// Persisted whole-site maintenance survives a process restart. Background SSL
// renewals and companion/file writers must not regenerate or mutate this site
// merely because its in-memory slot has disappeared.
func siteBackupMaintenanceBlocksSiteOp(siteID int) bool {
	if db := database.GetDB(); db != nil {
		var status string
		if err := db.QueryRow(`SELECT status FROM websites WHERE id=?`, siteID).Scan(&status); err != nil {
			return true
		}
		return status == "backup_maintenance"
	}
	return false
}

// Only the journal-checked recovery coordinator can claim this special slot.
func tryAcquireSiteBackupRecoveryOp(siteID int) bool {
	release, err := panelOperations.acquire()
	if err != nil {
		return false
	}
	claimed := false
	defer func() {
		if !claimed {
			release()
		}
	}()
	wpSiteOpMu.Lock()
	defer wpSiteOpMu.Unlock()
	if _, busy := wpSiteOpBusy[siteID]; busy {
		return false
	}
	db := database.GetDB()
	if db == nil {
		return false
	}
	var status string
	if err := db.QueryRow(`SELECT status FROM websites WHERE id=?`, siteID).Scan(&status); err != nil || status != "backup_maintenance" {
		return false
	}
	wpSiteOpBusy[siteID] = "site_backup_recovery"
	wpSiteOpOwners[siteID] = &siteOperationOwner{marker: 1}
	wpSiteOpLifecycleRelease[siteID] = release
	claimed = true
	return true
}

// ReleaseSiteOpLock releases a lock acquired by TryAcquireSiteOpLock. It is
// a no-op if the site currently holds no lock.
func ReleaseSiteOpLock(siteID int) {
	wpSiteOpMu.Lock()
	defer wpSiteOpMu.Unlock()
	delete(wpSiteOpBusy, siteID)
	delete(wpSiteOpOwners, siteID)
	if release := wpSiteOpLifecycleRelease[siteID]; release != nil {
		delete(wpSiteOpLifecycleRelease, siteID)
		release()
	}
}

// SiteOpLocked reports whether siteID currently holds a lock.
func SiteOpLocked(siteID int) bool {
	wpSiteOpMu.Lock()
	defer wpSiteOpMu.Unlock()
	_, busy := wpSiteOpBusy[siteID]
	return busy
}
