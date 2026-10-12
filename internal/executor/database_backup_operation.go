package executor

// A nonzero-sized identity uniquely identifies one acquired site operation.
// Releasing and reacquiring even the same reason produces a different owner.
type siteOperationOwner struct{ marker byte }

// DatabaseBackupSiteOperation is an opaque, in-memory proof for the administrator
// update's safety backup. It cannot be supplied through a JSON request or restored
// from persisted task metadata. Ordinary backups must acquire their own slot.
type DatabaseBackupSiteOperation struct {
	siteID int
	owner  *siteOperationOwner
}

func CaptureDatabaseBackupSiteOperation(siteID int) *DatabaseBackupSiteOperation {
	wpSiteOpMu.Lock()
	defer wpSiteOpMu.Unlock()
	owner := wpSiteOpOwners[siteID]
	if owner == nil || wpSiteOpBusy[siteID] != "wp_administrator_update" {
		return nil
	}
	return &DatabaseBackupSiteOperation{siteID: siteID, owner: owner}
}

func databaseBackupSiteOperationOwned(siteID int, inherited *DatabaseBackupSiteOperation) bool {
	wpSiteOpMu.Lock()
	defer wpSiteOpMu.Unlock()
	return inherited != nil && inherited.siteID == siteID && inherited.owner != nil &&
		wpSiteOpOwners[siteID] == inherited.owner && wpSiteOpBusy[siteID] == "wp_administrator_update"
}
