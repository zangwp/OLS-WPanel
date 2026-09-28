package executor

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/zangwp/OLS-WPanel/database"
)

func newSiteMigrationStoreTest(t *testing.T) (*siteMigrationStore, int) {
	t.Helper()
	database.Close()
	if err := database.Open(filepath.Join(t.TempDir(), "panel.db")); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	if err := database.RunMigrations(); err != nil {
		t.Fatal(err)
	}
	result, err := database.GetDB().Exec(`INSERT INTO websites
		(name,domain,system_user,web_root,log_dir,db_name,db_user,lsphp_socket_path,ols_vhost_config_path)
		VALUES ('example','example.com','wp_example','/www/example','/logs/example','db_example','user_example','/tmp/lshttpd/example.sock','/openlitespeed/example.conf')`)
	if err != nil {
		t.Fatal(err)
	}
	siteID64, _ := result.LastInsertId()
	if _, err := database.GetDB().Exec(`INSERT INTO site_migration_peers(id,status,protocol_version) VALUES ('peer_00000000001','paired',?)`, siteMigrationProtocolVersion); err != nil {
		t.Fatal(err)
	}
	if _, err := database.GetDB().Exec(`INSERT INTO site_migration_batches(id,peer_id,direction) VALUES ('batch_0000000001','peer_00000000001','source')`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.GetDB().Exec(`INSERT INTO site_migration_sites
		(id,batch_id,source_site_id,source_domain,target_domain,site_type,status,stage)
		VALUES ('migration_0000001','batch_0000000001',?,'example.com','example.com','wordpress','queued','publishing')`, siteID64); err != nil {
		t.Fatal(err)
	}
	store, err := newSiteMigrationStore(database.GetDB())
	if err != nil {
		t.Fatal(err)
	}
	return store, int(siteID64)
}

func TestLegacySiteMigrationRenderingFailsClosed(t *testing.T) {
	site := &siteMigrationFreezeSite{Domain: "example.com"}
	_, err := renderSiteMigrationMaintenance(site, "migration_0000001", strings.Repeat("m", 48))
	if err == nil || !strings.Contains(err.Error(), "OpenLiteSpeed") {
		t.Fatalf("renderSiteMigrationMaintenance() error = %v", err)
	}
	if _, err := injectSiteMigrationTargetMarker("", ""); err == nil || !strings.Contains(err.Error(), "OpenLiteSpeed") {
		t.Fatalf("injectSiteMigrationTargetMarker() error = %v", err)
	}
}
