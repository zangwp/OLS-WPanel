package executor

// SoftwareInstallErrorDetail bounds installation diagnostics and removes URL
// credentials before they are persisted in the panel's operation log.
func SoftwareInstallErrorDetail(err error) string {
	return systemPackageUpdateErrorDetail(err)
}
