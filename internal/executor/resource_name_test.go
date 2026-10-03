package executor

import (
	"path/filepath"
	"testing"

	"github.com/zangwp/OLS-WPanel/internal/config"
)

func TestBuildSiteNameAvoidsSeparatorCollisions(t *testing.T) {
	first := buildSiteName("ab.com")
	second := buildSiteName("a-b.com")
	if first == second {
		t.Fatalf("expected distinct resource names, got %q", first)
	}
}

func TestBuildSiteNameNormalizesEquivalentDomains(t *testing.T) {
	first := buildSiteName("Example.COM")
	second := buildSiteName(" example.com. ")
	if first != second {
		t.Fatalf("expected normalized domains to match, got %q and %q", first, second)
	}
}

func TestBuildSiteNameFitsSystemUserLimit(t *testing.T) {
	name := buildSiteName("this-is-a-very-long-domain-name-that-should-be-truncated.example.com")
	if len(name) > 27 {
		t.Fatalf("site name %q length = %d, want <= 27", name, len(name))
	}
	if len("php_"+name) > 32 {
		t.Fatalf("php user name length = %d, want <= 32", len("php_"+name))
	}
}

func TestShortResourcePathsFitLongDomain(t *testing.T) {
	domain := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc.example.com"
	siteName := buildSiteName(domain)
	cfg := &config.Config{}
	cfg.Paths.LSPHPSocketDir = "/run/php"

	phpSocket := filepath.Join(cfg.Paths.LSPHPSocketDir, siteConfigBaseName(siteName)+".sock")
	if err := validateUnixSocketPath(phpSocketPath(cfg, phpSocket, domain)); err != nil {
		t.Fatal(err)
	}
}

func TestPHPSocketPathPreservesStoredSocket(t *testing.T) {
	cfg := &config.Config{Paths: config.PathsConfig{LSPHPSocketDir: "/tmp/lshttpd"}}
	got := phpSocketPath(cfg, "/tmp/lshttpd/example.sock", "new.example.com")
	if got != "/tmp/lshttpd/example.sock" {
		t.Fatalf("expected stored socket path to be preserved, got %q", got)
	}
}

func TestOLSVHostEnabledPathUsesStoredConfigFilename(t *testing.T) {
	cfg := &config.Config{}
	cfg.Paths.OLSVHostsEnabled = "/etc/openlitespeed/sites-enabled"

	got := olsVHostEnabledPath(cfg, "/etc/openlitespeed/sites-available/vps17_top_0ea8c86a.conf", "vps17.top")
	want := filepath.Join("/etc/openlitespeed/sites-enabled", "vps17_top_0ea8c86a.conf")
	if got != want {
		t.Fatalf("olsVHostEnabledPath() = %q, want %q", got, want)
	}
}

func TestIsValidDomainRejectsLongLabel(t *testing.T) {
	domain := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.com"
	if IsValidDomain(domain) {
		t.Fatalf("expected long domain label to be rejected")
	}
}
