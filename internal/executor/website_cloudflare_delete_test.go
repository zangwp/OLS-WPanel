package executor

import (
	"testing"

	"github.com/zangwp/OLS-WPanel/internal/database"
)

func TestFinalWebsiteDeleteTransactionRejectsCloudflareEnabledOwnedOrPending(t *testing.T) {
	for _, condition := range []string{"enabled=1", "rule_id='owned-rule'", "pending_hash='uncertain-write'"} {
		t.Run(condition, func(t *testing.T) {
			openTestDB(t)
			db := database.GetDB()
			insertMinimalWebsite(t, "guard.example.com")
			mustExec(t, db, `INSERT INTO cron_jobs(name,cron_expression,command,task_type,site_id) VALUES('retained','*/5 * * * *','guard.example.com','wp_cron',1)`)
			mustExec(t, db, `INSERT INTO website_cloudflare_security(site_id,hostname,rule_ref) VALUES(1,'guard.example.com','owned-ref')`)
			mustExec(t, db, `UPDATE website_cloudflare_security SET `+condition+` WHERE site_id=1`)
			if deleted, err := deleteSiteAndAssociatedCronJobs(db, 1); err == nil || deleted {
				t.Fatal("direct final delete bypassed the Cloudflare guard", deleted, err)
			}
			var sites, jobs int
			if err := db.QueryRow(`SELECT COUNT(*) FROM websites WHERE id=1`).Scan(&sites); err != nil {
				t.Fatal(err)
			}
			if err := db.QueryRow(`SELECT COUNT(*) FROM cron_jobs WHERE site_id=1`).Scan(&jobs); err != nil || sites != 1 || jobs != 1 {
				t.Fatal("blocked transaction removed site or cron records", sites, jobs, err)
			}
		})
	}
}
