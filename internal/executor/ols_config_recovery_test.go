package executor

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOLSConfigFailedRecoveryReportsActualStagesAndKeepsOldFiles(t *testing.T) {
	fixture := newOLSIPv6RegistryFixture(t)
	oldRegistry := "old registry\n"
	if err := os.WriteFile(fixture.paths.managed, []byte(oldRegistry), 0640); err != nil {
		t.Fatal(err)
	}
	var validations int
	runOLSCommand = func(name string, args ...string) ([]byte, error) {
		if name != fixture.paths.binary || strings.Join(args, " ") != "-t" {
			t.Fatalf("failed validation must never restart the service: %s %v", name, args)
		}
		validations++
		return []byte("[WARN] existing locked site has invalid execution identity"), errors.New("exit status 1")
	}
	link := filepath.Join(fixture.enabled, "example.com.conf")
	err := applyOLSVHostConfig(nil, fixture.content+"# pending change\n", fixture.site, link)
	if err == nil || validations < 2 {
		t.Fatalf("failed validation or recovery was ignored: validations=%d err=%v", validations, err)
	}
	message := taskFailure("应用 OpenLiteSpeed 配置失败", err).Message
	for _, expected := range []string{"[WARN] existing locked site", "IPv4 配置回退也未通过", "恢复后重载失败", "自动恢复不完整"} {
		if !strings.Contains(message, expected) {
			t.Fatalf("missing actual failure %q: %s", expected, message)
		}
	}
	for _, unexpected := range []string{"<nil>", "恢复旧注册表失败", "旧状态已恢复", "注册表已恢复"} {
		if strings.Contains(message, unexpected) {
			t.Fatalf("reported an incorrect recovery result %q: %s", unexpected, message)
		}
	}
	if strings.Count(message, "应用 OpenLiteSpeed 配置失败") != 1 {
		t.Fatalf("application failure prefix was duplicated: %s", message)
	}
	if readOLSIPv6Registry(t, fixture) != oldRegistry {
		t.Fatal("failed recovery replaced the old registry")
	}
	content, readErr := os.ReadFile(fixture.site)
	if readErr != nil || string(content) != fixture.content {
		t.Fatalf("failed recovery lost the old vhost: %v", readErr)
	}
	target, readErr := os.Readlink(link)
	if readErr != nil || target != fixture.site {
		t.Fatalf("failed recovery lost the old enabled link: %v", readErr)
	}
}
