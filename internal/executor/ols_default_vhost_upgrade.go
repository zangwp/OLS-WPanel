package executor

import (
	"log"

	"github.com/zangwp/OLS-WPanel/internal/database"
)

func init() {
	database.RegisterUpgrade("1.0.70", ensureManagedOLSDefaultVHostIdentity)
}

// ensureManagedOLSDefaultVHostIdentity repairs the fallback virtual-host root
// emitted by older installers. OpenLiteSpeed rejects roots owned by UID 0 (or
// another identity below its minimum), so the directory must use the standard
// unprivileged web identity before the managed registry is validated again.
func ensureManagedOLSDefaultVHostIdentity() error {
	if err := ensureOLSDefaultVHost(currentOLSRuntimePaths()); err != nil {
		log.Printf("[升级] 修正 OpenLiteSpeed 备用虚拟主机身份失败，已跳过且不会阻止面板启动: %v", err)
		return nil
	}
	log.Printf("[升级] 已修正 OpenLiteSpeed 备用虚拟主机目录身份")
	return nil
}
