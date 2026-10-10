package executor

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/zangwp/OLS-WPanel/internal/cloudflaresecurity"
	"github.com/zangwp/OLS-WPanel/internal/database"
)

var cloudflareWebsiteSchedulerOnce sync.Once

// Network reconciliation runs independently so a slow Cloudflare account
// cannot delay local SSH/website Fail2ban lifecycle reconciliation.
func StartCloudflareWebsiteSyncScheduler() {
	cloudflareWebsiteSchedulerOnce.Do(func() {
		GoSafe(func() {
			SyncCloudflareWebsiteBans()
			ticker := time.NewTicker(2 * time.Minute)
			defer ticker.Stop()
			for range ticker.C {
				SyncCloudflareWebsiteBans()
			}
		})
	})
}

// Reconcile persisted desired website bans, including failed changes and
// uncertain remote responses, after the local Fail2ban lifecycle is refreshed.
func SyncCloudflareWebsiteBans() {
	db := database.GetDB()
	if db == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := cloudflaresecurity.NewService(db).SyncAll(ctx); err != nil {
		log.Printf("Cloudflare 网站规则同步未完成（将自动重试）: %v", err)
	}
}
