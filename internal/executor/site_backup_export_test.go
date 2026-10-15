package executor

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zangwp/OLS-WPanel/internal/models"
)

func siteBackupExportFixture(t *testing.T) (*models.Website, *models.SiteBackupManifest, string) {
	t.Helper()
	dir := t.TempDir()
	site := &models.Website{ID: 1, Domain: "example.com"}
	manifest := &models.SiteBackupManifest{Version: 1, SiteBackup: models.SiteBackup{ID: "22222222-2222-4222-8222-222222222222", SiteID: 1, CreatedAt: time.Now().UTC(), State: "complete", Consistency: "controlled_quiescence", Message: "diagnostic-secret"}, Domain: site.Domain, WebRoot: "/www/wwwroot/example.com", DBName: "site_db", DBUser: "site_user", SystemUser: "wp_site", TablePrefix: "wp_", Operation: "create", Phase: "completed", OriginalVHost: "PASSWORD=manifest-secret"}
	for name, body := range map[string]string{"files.tar.gz": "compressed website fixture", "database.sql.gz": "compressed SQL fixture"} {
		data := []byte(body)
		hash := sha256.Sum256(data)
		if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
			t.Fatal(err)
		}
		artifact := models.SiteBackupArtifact{Name: name, Size: int64(len(data)), SHA256: hex.EncodeToString(hash[:])}
		if name == "files.tar.gz" {
			manifest.Files = artifact
		} else {
			manifest.Database = artifact
		}
	}
	return site, manifest, dir
}

func TestCompleteSiteBackupExportContainsVerifiablePortableSet(t *testing.T) {
	site, manifest, dir := siteBackupExportFixture(t)
	bundle, err := prepareSiteBackupExport(context.Background(), site, manifest, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer bundle.Close()
	var output bytes.Buffer
	if err := bundle.Write(context.Background(), &output); err != nil {
		t.Fatal(err)
	}
	if int64(output.Len()) != bundle.Size() {
		t.Fatalf("Content-Length=%d actual=%d", bundle.Size(), output.Len())
	}
	if !strings.HasSuffix(bundle.Filename(), "_site-backup.tar") {
		t.Fatal(bundle.Filename())
	}
	archive := tar.NewReader(bytes.NewReader(output.Bytes()))
	entries := map[string][]byte{}
	for {
		header, err := archive.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if header.Typeflag != tar.TypeReg || header.Mode != 0600 || !strings.HasPrefix(header.Name, manifest.ID+"/") {
			t.Fatal("unsafe archive entry", header)
		}
		data, err := io.ReadAll(archive)
		if err != nil {
			t.Fatal(err)
		}
		entries[strings.TrimPrefix(header.Name, manifest.ID+"/")] = data
	}
	if len(entries) != 4 {
		t.Fatal("bundle must have exactly two components, manifest and checksums", entries)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(entries["SHA256SUMS"])), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			t.Fatal(line)
		}
		hash := sha256.Sum256(entries[fields[1]])
		if hex.EncodeToString(hash[:]) != fields[0] {
			t.Fatal("export checksum mismatch", line)
		}
	}
	var portable models.SiteBackupManifest
	if err := json.Unmarshal(entries["manifest.json"], &portable); err != nil {
		t.Fatal(err)
	}
	if portable.Files != manifest.Files || portable.Database != manifest.Database || portable.DBName != manifest.DBName || portable.WebRoot != manifest.WebRoot || portable.ID != manifest.ID {
		t.Fatal("portable restore binding changed", portable)
	}
	if bytes.Contains(entries["manifest.json"], []byte("secret")) || portable.OriginalVHost != "" || portable.Message != "" {
		t.Fatal("export leaked runtime configuration or diagnostics")
	}
}

func TestCompleteSiteBackupExportRejectsUnsafeAndChangedArtifacts(t *testing.T) {
	for _, name := range []string{"incomplete", "recovery_journal", "path_traversal", "oversized", "same_size_tampering", "cancelled", "symlink"} {
		t.Run(name, func(t *testing.T) {
			site, manifest, dir := siteBackupExportFixture(t)
			ctx := context.Background()
			switch name {
			case "incomplete":
				manifest.State = "failed"
			case "recovery_journal":
				manifest.Operation = "restore"
			case "path_traversal":
				manifest.Files.Name = "../files.tar.gz"
			case "oversized":
				manifest.Files.Size = fileRestoreMaxBytes + 1
			case "same_size_tampering":
				if err := os.WriteFile(filepath.Join(dir, "files.tar.gz"), bytes.Repeat([]byte("x"), int(manifest.Files.Size)), 0600); err != nil {
					t.Fatal(err)
				}
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "symlink":
				target := filepath.Join(dir, "outside")
				if err := os.Rename(filepath.Join(dir, "files.tar.gz"), target); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, filepath.Join(dir, "files.tar.gz")); err != nil {
					t.Skip("symlink creation unavailable", err)
				}
			}
			bundle, err := prepareSiteBackupExport(ctx, site, manifest, dir)
			if bundle != nil {
				bundle.Close()
			}
			if err == nil {
				t.Fatal("unsafe export prepared", name)
			}
		})
	}
}

type siteBackupExportFailWriter struct{ remaining int }

func (w *siteBackupExportFailWriter) Write(data []byte) (int, error) {
	if len(data) > w.remaining {
		return 0, errors.New("client disconnected")
	}
	w.remaining -= len(data)
	return len(data), nil
}

func TestCompleteSiteBackupExportInterruptsRatherThanFinishingInvalidStream(t *testing.T) {
	for _, name := range []string{"cancelled", "client_disconnected", "same_size_change_after_preparation", "size_change_after_preparation"} {
		t.Run(name, func(t *testing.T) {
			site, manifest, dir := siteBackupExportFixture(t)
			bundle, err := prepareSiteBackupExport(context.Background(), site, manifest, dir)
			if err != nil {
				t.Fatal(err)
			}
			defer bundle.Close()
			ctx := context.Background()
			var output bytes.Buffer
			var writer io.Writer = &output
			switch name {
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "client_disconnected":
				writer = &siteBackupExportFailWriter{remaining: 520}
			case "same_size_change_after_preparation":
				if err := os.WriteFile(filepath.Join(dir, "files.tar.gz"), bytes.Repeat([]byte("x"), int(manifest.Files.Size)), 0600); err != nil {
					t.Fatal(err)
				}
			case "size_change_after_preparation":
				if err := os.WriteFile(filepath.Join(dir, "files.tar.gz"), []byte("changed"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err := bundle.Write(ctx, writer); err == nil {
				t.Fatal("invalid stream finished successfully")
			}
			if int64(output.Len()) >= bundle.Size() {
				t.Fatal("failed stream looked complete")
			}
		})
	}
}

func TestCompleteSiteBackupExportCanonicalIDIsCheckedBeforePathAccess(t *testing.T) {
	for _, id := range []string{"../../etc", fmt.Sprintf("%032d", 1), "00000000-0000-0000-0000-000000000000"} {
		if _, err := PrepareSiteBackupExport(context.Background(), &models.Website{ID: 1, Domain: "example.com"}, id); err == nil {
			t.Fatal("invalid backup identity accepted", id)
		}
	}
}
