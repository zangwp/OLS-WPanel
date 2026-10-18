package executor

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/zangwp/OLS-WPanel/internal/database"
)

// Use the existing serialized queue once at startup when automatic maintenance
// is enabled but its cache is missing. The weekly timer remains unchanged.
func EnqueueInitialCloudflareRefresh() error {
	needed, err := needsInitialCloudflareRefresh(database.GetDB())
	if err != nil || !needed {
		return err
	}
	if err := refreshTrustedProxyReady(); err != nil {
		return err
	}
	_, err = GlobalQueue.EnqueueContext(context.Background(), TaskRefreshWhitelist, nil)
	return err
}

func needsInitialCloudflareRefresh(db *sql.DB) (bool, error) {
	automatic, err := automaticCloudflareProxyEnabled(db)
	if err != nil || !automatic {
		return false, err
	}
	var schedule string
	if err := db.QueryRow(`SELECT svalue FROM security_settings WHERE skey='auto_whitelist_enabled'`).Scan(&schedule); err != nil {
		return false, fmt.Errorf("read automatic IP maintenance setting: %w", err)
	}
	if strings.TrimSpace(schedule) != "true" {
		return false, nil
	}
	cache, err := readCachedSecurityIPRanges(db, "cloudflare_realip_ips")
	if err != nil {
		return false, err
	}
	return len(cache) == 0, nil
}
