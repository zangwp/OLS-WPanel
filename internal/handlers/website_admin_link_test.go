package handlers

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/zangwp/OLS-WPanel/internal/models"
)

func TestWordPressAdminURL(t *testing.T) {
	for _, tc := range []struct {
		name, siteType, siteURL, want string
		ssl                           bool
	}{
		{"root", "wordpress", "", "http://example.com/wp-admin/", false},
		{"https", "wordpress", "", "https://example.com/wp-admin/", true},
		{"subdirectory", "wordpress", "https://old.example/blog/?query=value", "https://example.com/blog/wp-admin/", true},
		{"reject script", "wordpress", "javascript:alert(1)", "http://example.com/wp-admin/", false},
		{"reject credentials", "wordpress", "https://user:password@old.example/blog", "http://example.com/wp-admin/", false},
		{"php site", "php", "", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			site := &models.Website{Domain: "example.com", SiteType: tc.siteType, SSLEnabled: tc.ssl}
			if got := wordPressAdminURL(site, tc.siteURL); got != tc.want {
				t.Fatalf("url=%q, want %q", got, tc.want)
			}
		})
	}
}

func TestRefreshWordPressTablePrefixUsesConfigOverStalePanelRecord(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "wp-config.php"), []byte("<?php\n$table_prefix = 'restored_';\n"), 0600); err != nil {
		t.Fatal(err)
	}
	site := &models.Website{WebRoot: root, TablePrefix: "old_random_"}
	refreshWordPressTablePrefix(site)
	if site.TablePrefix != "restored_" {
		t.Fatalf("stale panel prefix won over config: %s", site.TablePrefix)
	}
}
