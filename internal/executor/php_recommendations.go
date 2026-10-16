package executor

// RecommendOPcacheMemoryConsumptionMB recommends OPcache memory in MB.
// Memory tiers and site count determine the value, bounded by 64 MB and
// min(768 MB, 12.5% of RAM), then rounded down to a 32 MB multiple.
// Tiers avoid oversized caches on large servers from a fixed RAM percentage.
func RecommendOPcacheMemoryConsumptionMB(facts SystemFacts) int {
	totalMB := int(facts.TotalMemoryBytes / 1024 / 1024)

	var base int
	switch {
	case totalMB <= 512:
		base = 64
	case totalMB <= 1024:
		base = 96
	case totalMB <= 2048:
		base = 128
	case totalMB <= 4096:
		base = 192
	case totalMB <= 8192:
		base = 256
	case totalMB <= 16384:
		base = 384
	default:
		base = 512
	}

	var siteAdjust int
	switch {
	case facts.SiteCount <= 3:
		siteAdjust = 0
	case facts.SiteCount <= 8:
		siteAdjust = 32
	case facts.SiteCount <= 20:
		siteAdjust = 64
	case facts.SiteCount <= 40:
		siteAdjust = 128
	default:
		siteAdjust = 256
	}

	hardCap := totalMB * 125 / 1000 // 12.5% of total RAM
	if hardCap > 768 {
		hardCap = 768
	}
	if hardCap < 64 {
		hardCap = 64
	}

	result := base + siteAdjust
	if result > hardCap {
		result = hardCap
	}
	if result < 64 {
		result = 64
	}

	result = (result / 32) * 32
	if result < 64 {
		result = 64
	}
	return result
}

// RecommendLSPHPMaxChildren recommends a new site's PHP child-process limit.
// It uses the lower RAM or CPU limit and is persisted when the site is created.
// Managed vhosts start PHP parents with OLS; children scale with requests.
// This per-site concurrency limit is not a server-wide memory budget; busy
// sites still require tuning against actual resource usage.
func RecommendLSPHPMaxChildren(facts SystemFacts) int {
	totalMB := int(facts.TotalMemoryBytes / 1024 / 1024)

	var memoryCap int
	switch {
	case totalMB < 768:
		memoryCap = 2
	case totalMB < 1536:
		memoryCap = 4
	case totalMB < 3072:
		memoryCap = 6
	case totalMB < 6144:
		memoryCap = 10
	case totalMB < 12288:
		memoryCap = 16
	case totalMB < 24576:
		memoryCap = 24
	default:
		memoryCap = 32
	}

	var cpuCap int
	switch {
	case facts.CPUCores <= 1:
		cpuCap = 6
	case facts.CPUCores == 2:
		cpuCap = 10
	case facts.CPUCores <= 4:
		cpuCap = 16
	case facts.CPUCores <= 8:
		cpuCap = 24
	case facts.CPUCores <= 16:
		cpuCap = 32
	default:
		cpuCap = 48
	}

	if memoryCap < cpuCap {
		return memoryCap
	}
	return cpuCap
}

// RecommendOPcacheMaxAcceleratedFiles recommends opcache.max_accelerated_files.
// PHP rounds up to predefined prime hash-table sizes. Return those sizes
// directly by site count so the configured and effective values match.
func RecommendOPcacheMaxAcceleratedFiles(facts SystemFacts) int {
	switch {
	case facts.SiteCount <= 1:
		return 16229
	case facts.SiteCount <= 3:
		return 32531
	case facts.SiteCount <= 8:
		return 65407
	case facts.SiteCount <= 20:
		return 130987
	case facts.SiteCount <= 50:
		return 262237
	default:
		return 524521
	}
}
