package executor

import (
	"strings"
	"testing"

	"github.com/zangwp/OLS-WPanel/internal/config"
)

func TestRenderSiteLogrotateConfigIncludesAllSiteLogs(t *testing.T) {
	config := renderSiteLogrotateConfig("example.com", "/www/wwwlogs/example.com", defaultSiteLogRetentionDays)
	for _, want := range []string{
		"/www/wwwlogs/example.com/access.log",
		"/www/wwwlogs/example.com/error.log",
		"/www/wwwlogs/example.com/wp-security.log",
		"/www/wwwlogs/example.com/wp-login-security.log",
		"/www/wwwlogs/example.com/wp-sqli-security.log",
		"/www/wwwlogs/example.com/php-error.log",
		"/www/wwwlogs/example.com/php-slow.log",
		"rotate 14",
		"dateext",
		"dateformat -%Y-%m-%d",
		"dateyesterday",
		"copytruncate",
	} {
		if !strings.Contains(config, want) {
			t.Fatalf("logrotate config missing %q:\n%s", want, config)
		}
	}
}

func TestCleanSiteLogrotateLogDirRejectsOutsideRoot(t *testing.T) {
	for _, input := range []string{
		"/tmp/example.com",
		"/www/wwwlogs/../secret",
		"www/wwwlogs/example.com",
		"",
	} {
		if _, err := cleanSiteLogrotateLogDir(input); err == nil {
			t.Fatalf("expected %q to be rejected", input)
		}
	}
}

func TestCleanSiteLogrotateLogDirAllowsSiteLogRoot(t *testing.T) {
	got, err := cleanSiteLogrotateLogDir("/www/wwwlogs/example.com/../example.com")
	if err != nil {
		t.Fatalf("expected site log dir to be accepted: %v", err)
	}
	if got != "/www/wwwlogs/example.com" {
		t.Fatalf("clean log dir = %q", got)
	}
}

func TestCleanSiteLogrotateLogDirHonorsConfiguredRoot(t *testing.T) {
	old := config.AppConfig
	config.AppConfig = &config.Config{}
	config.AppConfig.Paths.WWWLogs = "/srv/site-logs"
	t.Cleanup(func() { config.AppConfig = old })
	got, err := cleanSiteLogrotateLogDir("/srv/site-logs/example.com/../example.com")
	if err != nil || got != "/srv/site-logs/example.com" {
		t.Fatalf("custom log root was not honored: got=%q err=%v", got, err)
	}
	for _, value := range []string{"/www/wwwlogs/example.com", "/srv/site-logs-other/example.com", "/srv/site-logs/../private", "/srv/site-logs/a\n}", "/srv/site-logs/*"} {
		if _, err := cleanSiteLogrotateLogDir(value); err == nil {
			t.Fatalf("outside/injected log path accepted: %q", value)
		}
	}
	config.AppConfig.Paths.WWWLogs = "/srv/logs\ninclude /tmp/unsafe"
	if _, err := cleanSiteLogrotateLogDir("/srv/site-logs/example.com"); err == nil {
		t.Fatal("unsafe configured log root accepted")
	}
}
