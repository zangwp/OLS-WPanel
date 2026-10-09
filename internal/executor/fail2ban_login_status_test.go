package executor

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/zangwp/OLS-WPanel/internal/config"
)

func TestFail2banWebsiteLogRootRejectsINIAndGlobInjection(t *testing.T) {
	for _, value := range []string{"", "relative", "/", "/tmp/logs\n[sshd]", "/tmp/logs\r", "/tmp/log s", "/tmp/*", "/tmp/a?", "/tmp/[logs]", "/tmp/{logs}", "/tmp/%(oops)s", "/tmp/a#b", "/tmp/a;b", " /tmp/logs"} {
		if _, err := cleanFail2banWebsiteLogRoot(value); err == nil {
			t.Fatalf("unsafe log root accepted: %q", value)
		}
	}
	content := "[olswpanel]\nlogpath = /www/wwwlogs/*/access.log\n          /www/wwwlogs/*/error.log\n[olswpanel-login]\nlogpath = /www/wwwlogs/*/wp-login-security.log\n[olswpanel-sqli]\nlogpath = /www/wwwlogs/*/access.log\n[olswpanel-sshd]\nlogpath = /var/log/auth.log\n"
	got, err := renderFail2banWebsiteLogPaths(content, "/srv/site-logs")
	if err != nil || strings.Contains(got, "/www/wwwlogs/") || strings.Count(got, "/srv/site-logs/") != 4 || !strings.Contains(got, "logpath = /var/log/auth.log") {
		t.Fatalf("website paths not synchronized, got=%q err=%v", got, err)
	}
}

func TestWPLoginFailureJailMatchesOnlyExactLoadedSource(t *testing.T) {
	oldConfig, oldRead := config.AppConfig, readFail2banLoginLogPaths
	config.AppConfig = &config.Config{}
	config.AppConfig.Paths.WWWLogs = "/srv/site-logs"
	t.Cleanup(func() { config.AppConfig, readFail2banLoginLogPaths = oldConfig, oldRead })
	path := "/srv/site-logs/site.example/wp-login-security.log"
	var output string
	readFail2banLoginLogPaths = func(ctx context.Context) (string, error) {
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > 500*time.Millisecond {
			t.Fatal("live jail lookup is not bounded to 500ms")
		}
		return output, nil
	}
	for _, text := range []string{
		"Current monitored log file(s):\n`- " + path,
		"Current monitored log file(s):\n|- /srv/site-logs/other.example/wp-login-security.log\n`- " + path,
	} {
		output = text
		if !WPLoginFailureJailMatches(context.Background(), path) {
			t.Fatalf("loaded exact source was not recognized: %q", text)
		}
	}
	for _, text := range []string{
		"No log file is currently monitored",
		"Current monitored log file(s):\n`- /www/wwwlogs/site.example/wp-login-security.log",
		"Current monitored log file(s):\n`- " + path + ".old",
		"Current monitored log file(s):\n`- /srv/site-logs/*/wp-login-security.log",
		"Status for the jail: olswpanel-login",
	} {
		output = text
		if WPLoginFailureJailMatches(context.Background(), path) {
			t.Fatalf("unwatched source falsely reported ready: %q", text)
		}
	}
	readFail2banLoginLogPaths = func(context.Context) (string, error) { return "", errors.New("jail missing") }
	if WPLoginFailureJailMatches(context.Background(), path) {
		t.Fatal("failed live jail lookup falsely reported ready")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	readFail2banLoginLogPaths = func(context.Context) (string, error) { t.Fatal("cancelled request executed a command"); return "", nil }
	if WPLoginFailureJailMatches(ctx, path) {
		t.Fatal("cancelled request falsely reported ready")
	}
}
