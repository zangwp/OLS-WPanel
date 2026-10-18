package executor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zangwp/OLS-WPanel/internal/database"
	"github.com/zangwp/OLS-WPanel/internal/models"
)

func legacySiteBackupMaintenanceFixture(site *models.Website, root, marker string, metadata bool) string {
	domains, _ := normalizeOLSDomains(site.Domain, splitAliases(site.Aliases))
	var out strings.Builder
	fmt.Fprintf(&out, "# OLS-WPanel-Format: 1\n# OLS-WPanel-VHost: olsw_%s\n# OLS-WPanel-Domains: %s\n# OLS-WPanel-VHRoot: %s\n", buildSiteName(site.Domain), strings.Join(domains, ","), root)
	if metadata {
		fmt.Fprintf(&out, "# OLS-WPanel-SystemUser: %s\n", site.SystemUser)
	}
	fmt.Fprintf(&out, "docRoot %s\nvhDomain %s\n", root, site.Domain)
	if len(domains) > 1 {
		fmt.Fprintf(&out, "vhAliases %s\n", strings.Join(domains[1:], ","))
	}
	fmt.Fprintf(&out, "enableGzip 0\nindex {\n useServer 0\n indexFiles maintenance.html\n}\ncontext / {\n type NULL\n location %s/\n allowBrowse 1\n extraHeaders <<<END_headers\nCache-Control: no-store\nX-OLS-WPanel-Backup: %s\nEND_headers\n}\nrewrite {\n enable 1\n autoLoadHtaccess 0\n rules <<<END_rules\nRewriteRule ^ - [R=503,L]\nEND_rules\n}\n", root, marker)
	if site.SSLEnabled {
		fmt.Fprintf(&out, "vhssl {\n keyFile %s\n certFile %s\n certChain 1\n sslProtocol %d\n}\n", site.SSLKeyPath, site.SSLCertPath, olsTLSProtocols)
	}
	return out.String()
}

func TestSiteBackupThawPreservesMaintenanceFingerprintAcrossTemplateUpgrade(t *testing.T) {
	for _, shape := range []string{"legacy", "legacy metadata", "current", "journal verified bytes"} {
		checkpoints := []string{"maintenance", "original vhost"}
		if shape == "journal verified bytes" {
			checkpoints = []string{"maintenance"}
		}
		for _, checkpoint := range checkpoints {
			t.Run(shape+"/"+checkpoint, func(t *testing.T) {
				f, _, _ := siteBackupPairedFixture(t)
				f.manifest.Phase = "freeze_failed"
				f.manifest.DBAccountLocked = true
				f.manifest.OriginalVHost = "original vhost"
				f.manifest.VHostPath = filepath.Join(t.TempDir(), "site.conf")
				f.site.OLSVHostConfigPath = f.manifest.VHostPath
				f.manifest.MaintenanceRoot = t.TempDir()
				f.manifest.Marker = "a31a9b36-2d77-4d82-8f55-b64fe66f4474"
				maintenance := legacySiteBackupMaintenanceFixture(f.site, f.manifest.MaintenanceRoot, f.manifest.Marker, shape == "legacy metadata")
				if shape == "current" {
					var err error
					maintenance, err = renderSiteBackupMaintenance(f.site, f.manifest.MaintenanceRoot, f.manifest.Marker)
					if err != nil {
						t.Fatal(err)
					}
				} else if shape == "journal verified bytes" {
					maintenance += "# preserved historical formatting\n"
				}
				digest := sha256.Sum256([]byte(maintenance))
				fingerprint := hex.EncodeToString(digest[:])
				f.manifest.MaintenanceVHostSHA256 = fingerprint
				initial := maintenance
				if checkpoint == "original vhost" {
					initial = f.manifest.OriginalVHost
				}
				if err := os.WriteFile(f.manifest.VHostPath, []byte(initial), 0640); err != nil {
					t.Fatal(err)
				}
				if _, err := database.DB.Exec("UPDATE websites SET ols_vhost_config_path=? WHERE id=1", f.manifest.VHostPath); err != nil {
					t.Fatal(err)
				}
				oldSQL, oldRestart, oldWrite, oldTraffic, oldStop := siteBackupSQL, siteBackupRestartOLS, siteBackupWriteVHost, siteBackupVerifyTraffic, siteBackupStopUser
				t.Cleanup(func() {
					siteBackupSQL, siteBackupRestartOLS, siteBackupWriteVHost, siteBackupVerifyTraffic, siteBackupStopUser = oldSQL, oldRestart, oldWrite, oldTraffic, oldStop
				})
				locks, unlocks, restarts := 0, 0, 0
				siteBackupSQL = func(_ context.Context, _ string, query string) (string, error) {
					if strings.HasSuffix(query, "ACCOUNT LOCK") {
						locks++
					} else if strings.HasSuffix(query, "ACCOUNT UNLOCK") {
						unlocks++
					}
					if strings.Contains(query, "SELECT COUNT(*)") {
						return "0", nil
					}
					return "", nil
				}
				restartFailure := errors.New("fixture OLS restart failure")
				siteBackupRestartOLS = func() ([]byte, error) {
					restarts++
					if restarts == 1 {
						return nil, restartFailure
					}
					return nil, nil
				}
				siteBackupWriteVHost = func(path string, data []byte, mode os.FileMode) error { return os.WriteFile(path, data, mode) }
				siteBackupStopUser = func(context.Context, *models.Website) error { return nil }
				siteBackupVerifyTraffic = func(_ context.Context, _ *models.Website, _ string, inMaintenance bool) error {
					if inMaintenance {
						assertFullRestoreFile(t, f.manifest.VHostPath, maintenance)
					}
					return nil
				}
				if err := f.thaw(context.Background()); !errors.Is(err, restartFailure) {
					t.Fatalf("first thaw error = %v", err)
				}
				assertFullRestoreFile(t, f.manifest.VHostPath, maintenance)
				data, err := os.ReadFile(filepath.Join(f.dir, "manifest.json"))
				if err != nil {
					t.Fatal(err)
				}
				var durable models.SiteBackupManifest
				if err := json.Unmarshal(data, &durable); err != nil {
					t.Fatal(err)
				}
				if durable.MaintenanceVHostSHA256 != fingerprint || !durable.DBAccountLocked || !durable.RequiresAttention {
					t.Fatal("failed thaw changed the journal fingerprint or lost maintenance ownership")
				}
				f.manifest = &durable
				if err := f.thaw(context.Background()); err != nil {
					t.Fatal(err)
				}
				assertFullRestoreFile(t, f.manifest.VHostPath, f.manifest.OriginalVHost)
				var status string
				if err := database.DB.QueryRow("SELECT status FROM websites WHERE id=1").Scan(&status); err != nil || status != "active" || locks != 1 || unlocks != 2 || f.manifest.MaintenanceVHostSHA256 != fingerprint {
					t.Fatalf("retry status=%s locks=%d unlocks=%d error=%v", status, locks, unlocks, err)
				}
			})
		}
	}
}

func TestSiteBackupThawRejectsUnknownMaintenanceFingerprintBeforeUnlock(t *testing.T) {
	for _, current := range []string{"original vhost", "unrecognized maintenance"} {
		t.Run(current, func(t *testing.T) {
			f, _, _ := siteBackupPairedFixture(t)
			f.manifest.OriginalVHost = "original vhost"
			f.manifest.VHostPath = filepath.Join(t.TempDir(), "site.conf")
			f.site.OLSVHostConfigPath = f.manifest.VHostPath
			f.manifest.MaintenanceRoot = t.TempDir()
			f.manifest.Marker = "a31a9b36-2d77-4d82-8f55-b64fe66f4474"
			f.manifest.DBAccountLocked = true
			f.manifest.MaintenanceVHostSHA256 = strings.Repeat("a", 64)
			if err := os.WriteFile(f.manifest.VHostPath, []byte(current), 0640); err != nil {
				t.Fatal(err)
			}
			if _, err := database.DB.Exec("UPDATE websites SET ols_vhost_config_path=? WHERE id=1", f.manifest.VHostPath); err != nil {
				t.Fatal(err)
			}
			oldSQL, oldRestart, oldWrite := siteBackupSQL, siteBackupRestartOLS, siteBackupWriteVHost
			t.Cleanup(func() { siteBackupSQL, siteBackupRestartOLS, siteBackupWriteVHost = oldSQL, oldRestart, oldWrite })
			siteBackupSQL = func(context.Context, string, string) (string, error) {
				t.Fatal("unverified maintenance unlocked DB")
				return "", nil
			}
			siteBackupRestartOLS = func() ([]byte, error) { t.Fatal("unverified maintenance restarted OLS"); return nil, nil }
			siteBackupWriteVHost = func(string, []byte, os.FileMode) error { t.Fatal("unverified maintenance replaced config"); return nil }
			if err := f.thaw(context.Background()); err == nil {
				t.Fatal("unknown journal fingerprint accepted")
			}
			assertFullRestoreFile(t, f.manifest.VHostPath, current)
			if f.manifest.MaintenanceVHostSHA256 != strings.Repeat("a", 64) || !f.manifest.DBAccountLocked {
				t.Fatal("rejection changed journal identity or DB ownership")
			}
		})
	}
}
