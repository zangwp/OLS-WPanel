package executor

import (
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zangwp/OLS-WPanel/internal/config"
	"github.com/zangwp/OLS-WPanel/internal/database"
	"github.com/zangwp/OLS-WPanel/internal/models"
)

func setupWebsiteDeleteReliabilityTest(t *testing.T) *models.Website {
	t.Helper()
	openTestDB(t)
	insertMinimalWebsite(t, "delete.example.com")
	root := t.TempDir()
	oldConfig, oldSecrets := config.AppConfig, siteSecretsRoot
	oldUser, oldRemove, oldRemoveAll := deleteSiteUser, deleteSiteRemove, deleteSiteRemoveAll
	oldDatabase, oldReload := deleteSiteDatabase, deleteSiteReload
	t.Cleanup(func() {
		config.AppConfig, siteSecretsRoot = oldConfig, oldSecrets
		deleteSiteUser, deleteSiteRemove, deleteSiteRemoveAll = oldUser, oldRemove, oldRemoveAll
		deleteSiteDatabase, deleteSiteReload = oldDatabase, oldReload
	})
	cfg := &config.Config{Paths: config.PathsConfig{
		WWWRoot: filepath.Join(root, "www"), WWWLogs: filepath.Join(root, "logs"),
		LSPHPSocketDir: filepath.Join(root, "sockets"), Certificates: filepath.Join(root, "certs"),
		OLSVHostsAvailable: filepath.Join(root, "available"), OLSVHostsEnabled: filepath.Join(root, "enabled"),
	}}
	config.AppConfig = cfg
	siteSecretsRoot = filepath.Join(root, "secrets")
	site := &models.Website{ID: 1, Domain: "delete.example.com", SystemUser: "wp_delete",
		WebRoot: filepath.Join(cfg.Paths.WWWRoot, "delete"), LogDir: filepath.Join(cfg.Paths.WWWLogs, "delete"),
		LSPHPSocketPath:    filepath.Join(cfg.Paths.LSPHPSocketDir, "delete.sock"),
		OLSVHostConfigPath: filepath.Join(cfg.Paths.OLSVHostsAvailable, "delete.conf"), DBName: "db1", DBUser: "u1"}
	for _, path := range []string{site.WebRoot, site.LogDir, cfg.Paths.OLSVHostsAvailable, cfg.Paths.OLSVHostsEnabled} {
		if err := os.MkdirAll(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(site.WebRoot, "index.php"), []byte("site content"), 0600); err != nil {
		t.Fatal(err)
	}
	deleteSiteUser = func(string) error { return nil }
	deleteSiteDatabase = func(string, string, *config.Config) error { return nil }
	deleteSiteReload = func(string) ([]byte, error) { return nil, nil }
	deleteSiteRemove = func(path string) error {
		if !strings.HasPrefix(path, root+string(filepath.Separator)) {
			return nil // No test mutation of /etc/logrotate.d.
		}
		return os.Remove(path)
	}
	return site
}

func TestDeleteSitePreservesRecordUntilFilesystemRetrySucceeds(t *testing.T) {
	site := setupWebsiteDeleteReliabilityTest(t)
	deleteSiteRemoveAll = func(path string) error {
		if path == site.WebRoot {
			return os.ErrPermission
		}
		return os.RemoveAll(path)
	}
	task := &Task{Payload: &DeleteSitePayload{Site: site}}
	result := executeDeleteSite(task)
	if result.Success || !strings.Contains(result.Message, "网站目录") {
		t.Fatalf("result = %#v", result)
	}
	var status string
	if err := database.GetDB().QueryRow("SELECT status FROM websites WHERE id=1").Scan(&status); err != nil || status != string(models.StatusDeleting) {
		t.Fatalf("retryable record = %q, error = %v", status, err)
	}
	if _, err := os.Stat(filepath.Join(site.WebRoot, "index.php")); err != nil {
		t.Fatalf("injected failure must retain the actual remaining file: %v", err)
	}
	deleteSiteRemoveAll = os.RemoveAll
	if result := executeDeleteSite(task); !result.Success {
		t.Fatalf("retry = %#v", result)
	}
	var count int
	if err := database.GetDB().QueryRow("SELECT COUNT(*) FROM websites WHERE id=1").Scan(&count); err != nil || count != 0 {
		t.Fatalf("record remains after successful retry: %d, %v", count, err)
	}
	if _, err := os.Stat(site.WebRoot); !os.IsNotExist(err) {
		t.Fatalf("website directory remains: %v", err)
	}
}

func TestDeleteSiteRetainsRecordAndReportsIndependentFailures(t *testing.T) {
	site := setupWebsiteDeleteReliabilityTest(t)
	deleteSiteUser = func(string) error { return errors.New("user still running") }
	deleteSiteDatabase = func(string, string, *config.Config) error { return errors.New("database offline") }
	result := executeDeleteSite(&Task{Payload: &DeleteSitePayload{Site: site}})
	if result.Success || !strings.Contains(result.Message, "user still running") || !strings.Contains(result.Message, "database offline") {
		t.Fatalf("result = %#v", result)
	}
	var status string
	if err := database.GetDB().QueryRow("SELECT status FROM websites WHERE id=1").Scan(&status); err != nil || status != string(models.StatusDeleting) {
		t.Fatalf("retryable record = %q, error = %v", status, err)
	}
}

func TestRemoveWebsiteSystemUserAcceptsOnlyVerifiedAbsence(t *testing.T) {
	t.Run("already absent", func(t *testing.T) {
		err := removeWebsiteSystemUserWith("wp_delete", func(name string) (*user.User, error) {
			return nil, user.UnknownUserError(name)
		}, func(string, ...string) (string, error) {
			t.Fatal("userdel must not run for absent account")
			return "", nil
		})
		if err != nil {
			t.Fatal(err)
		}
	})
	t.Run("command succeeds but account remains", func(t *testing.T) {
		err := removeWebsiteSystemUserWith("wp_delete", func(name string) (*user.User, error) {
			return &user.User{Username: name}, nil
		}, func(string, ...string) (string, error) { return "", nil })
		if err == nil {
			t.Fatal("success reported for a remaining account")
		}
	})
	t.Run("lookup unavailable", func(t *testing.T) {
		err := removeWebsiteSystemUserWith("wp_delete", func(string) (*user.User, error) {
			return nil, errors.New("lookup failed")
		}, func(string, ...string) (string, error) {
			t.Fatal("unknown lookup failure must not be treated as account existence")
			return "", nil
		})
		if err == nil {
			t.Fatal("lookup error ignored")
		}
	})
}
