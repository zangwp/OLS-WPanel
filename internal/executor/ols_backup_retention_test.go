package executor

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestOLSConfigUpdatesBoundBackupsAndKeepOtherSites(t *testing.T) {
	for _, paused := range []bool{false, true} {
		t.Run(fmt.Sprintf("paused=%t", paused), func(t *testing.T) {
			fixture := newOLSIPv6RegistryFixture(t)
			olsIPv6Available = func() bool { return false }
			runOLSCommand = func(string, ...string) ([]byte, error) { return []byte("ok"), nil }
			link := filepath.Join(fixture.enabled, "example.com.conf")
			if paused {
				if err := os.Remove(link); err != nil {
					t.Fatal(err)
				}
			}
			engine := NewTemplateEngine(t.TempDir())
			backupDir := filepath.Join(engine.BackupDir, "openlitespeed")
			if err := os.MkdirAll(backupDir, 0750); err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{"other.com.conf.bak.1", "example.com.conf.bak.manual"} {
				if err := os.WriteFile(filepath.Join(backupDir, name), []byte("preserve"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			content := fixture.content
			// Initial content is revision 0. Eight successful updates must retain
			// revisions 1..7 as backups, independently of the site's enabled state.
			for revision := 1; revision <= olsVHostConfigBackupKeepCount+1; revision++ {
				content = fixture.content + fmt.Sprintf("# revision %d\n", revision)
				var err error
				if paused {
					err = engine.ApplyOLSVHostConfigKeepDisabled(content, fixture.site)
				} else {
					err = applyOLSVHostConfig(engine, content, fixture.site, link)
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			entries, err := os.ReadDir(backupDir)
			if err != nil {
				t.Fatal(err)
			}
			var revisions []string
			for _, entry := range entries {
				suffix := strings.TrimPrefix(entry.Name(), "example.com.conf.bak.")
				if suffix == entry.Name() {
					continue
				}
				if _, err := strconv.ParseInt(suffix, 10, 64); err != nil {
					continue
				}
				old, err := os.ReadFile(filepath.Join(backupDir, entry.Name()))
				if err != nil {
					t.Fatal(err)
				}
				if bytes.Equal(old, []byte(fixture.content)) {
					t.Fatal("oldest backup survived after the retention limit")
				}
				revisions = append(revisions, string(old))
			}
			if len(revisions) != olsVHostConfigBackupKeepCount {
				t.Fatalf("retained %d backups, want %d", len(revisions), olsVHostConfigBackupKeepCount)
			}
			for revision := 1; revision <= olsVHostConfigBackupKeepCount; revision++ {
				want := fixture.content + fmt.Sprintf("# revision %d\n", revision)
				found := false
				for _, old := range revisions {
					found = found || old == want
				}
				if !found {
					t.Fatalf("missing backed-up revision %d", revision)
				}
			}
			for _, name := range []string{"other.com.conf.bak.1", "example.com.conf.bak.manual"} {
				if data, err := os.ReadFile(filepath.Join(backupDir, name)); err != nil || string(data) != "preserve" {
					t.Fatalf("unrelated file changed: %s: %v", name, err)
				}
			}
			current, err := os.ReadFile(fixture.site)
			if err != nil || string(current) != content {
				t.Fatal("latest site configuration was not retained")
			}
			before, _ := os.ReadDir(backupDir)
			if paused {
				err = engine.ApplyOLSVHostConfigKeepDisabled(content, fixture.site)
			} else {
				err = applyOLSVHostConfig(engine, content, fixture.site, link)
			}
			if err != nil {
				t.Fatal(err)
			}
			after, _ := os.ReadDir(backupDir)
			if len(before) != len(after) {
				t.Fatal("unchanged configuration created an unnecessary backup")
			}
			if paused {
				if _, err := os.Lstat(link); !os.IsNotExist(err) {
					t.Fatal("updating a paused configuration enabled the site")
				}
			}
		})
	}
}
