package executor

import (
	"runtime"

	"github.com/zangwp/OLS-WPanel/internal/database"
)

// SystemFacts holds total RAM, CPU cores, and site count for adaptive defaults.
// Collect fresh facts when recommendations are needed because site counts
// change; reading /proc/meminfo and counting sites is inexpensive. Batch
// operations should collect once and reuse the result across sites.
type SystemFacts struct {
	TotalMemoryBytes uint64
	CPUCores         int
	SiteCount        int
}

// CollectSystemFacts reads current hardware and site counts.
func CollectSystemFacts() SystemFacts {
	return SystemFacts{
		TotalMemoryBytes: uint64(getTotalMemoryKB()) * 1024,
		CPUCores:         runtime.NumCPU(),
		SiteCount:        TotalSiteCount(),
	}
}

// TotalSiteCount counts all managed sites regardless of status.
func TotalSiteCount() int {
	if database.DB == nil {
		return 0
	}
	var count int
	if err := database.DB.QueryRow("SELECT COUNT(*) FROM websites").Scan(&count); err != nil {
		return 0
	}
	return count
}
