package handlers

import "github.com/zangwp/OLS-WPanel/internal/executor"

func (h *SoftwareHandler) invalidateCompletedSystemUpdate() {
	if h.Config != nil {
		invalidateSoftwareProbesForSystemUpdate(executor.ReadSystemPackageUpdateStatus(h.Config))
	}
}

func invalidateSoftwareProbesForSystemUpdate(status executor.SystemPackageUpdateStatus) {
	if status.ID == "" || (status.Status != "success" && status.Status != "failed") {
		return
	}
	// A failed update may already have changed packages before a later step
	// failed. Both terminal states require current version and health probes.
	softwareReadCache.invalidateFor("system-update:" + status.ID + ":" + status.UpdatedAt + ":" + status.Status)
}
