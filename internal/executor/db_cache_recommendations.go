package executor

// RecommendInnoDBBufferPoolSizeMB recommends an InnoDB buffer pool size in MB.
// MariaDB shares the host with LSPHP, Redis, OpenLiteSpeed, and the panel, so
// memory tiers use roughly 12.5-25% of RAM rather than dedicated-server ratios.
// A 30% cap protects other services even if the tier values are misconfigured.
func RecommendInnoDBBufferPoolSizeMB(facts SystemFacts) int {
	totalMB := int(facts.TotalMemoryBytes / 1024 / 1024)

	var recommended int
	switch {
	case totalMB <= 512:
		recommended = 64
	case totalMB <= 1024:
		recommended = 128
	case totalMB <= 2048:
		recommended = 384
	case totalMB <= 4096:
		recommended = 768
	case totalMB <= 8192:
		recommended = 1536
	case totalMB <= 16384:
		recommended = 3072
	case totalMB <= 32768:
		recommended = 6144
	default:
		recommended = totalMB / 4 // 25% of total RAM
		if recommended > 12288 {
			recommended = 12288
		}
	}

	hardCap := totalMB * 3 / 10 // 30% of total RAM
	if recommended > hardCap {
		recommended = hardCap
	}
	if recommended < 32 {
		recommended = 32
	}
	return recommended
}

// RecommendRedisMaxmemoryMB recommends Redis maxmemory in MB.
// Allocator overhead, fragmentation, and persistence forks consume memory
// beyond maxmemory. Cap defaults at 10% of RAM and 1024 MB; larger WordPress
// object caches require deliberate tuning.
func RecommendRedisMaxmemoryMB(facts SystemFacts) int {
	totalMB := int(facts.TotalMemoryBytes / 1024 / 1024)

	var recommended int
	switch {
	case totalMB <= 512:
		recommended = 32
	case totalMB <= 1024:
		recommended = 64
	case totalMB <= 2048:
		recommended = 128
	case totalMB <= 4096:
		recommended = 192
	case totalMB <= 8192:
		recommended = 256
	case totalMB <= 16384:
		recommended = 512
	case totalMB <= 32768:
		recommended = 768
	default:
		recommended = 1024
	}

	hardCap := totalMB / 10 // 10% of total RAM
	if hardCap > 1024 {
		hardCap = 1024
	}
	if recommended > hardCap {
		recommended = hardCap
	}
	if recommended < 16 {
		recommended = 16
	}
	return recommended
}
