package executor

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestWhitelistTimerSchedulesInsteadOfStartingRefreshService(t *testing.T) {
	directory := t.TempDir()
	var commands []string
	err := deployWhitelistTimer(func(path string, data []byte, mode os.FileMode) error {
		if mode != 0644 || filepath.ToSlash(filepath.Dir(path)) != "/etc/systemd/system" {
			t.Fatalf("unexpected unit write: %s mode=%v", path, mode)
		}
		return os.WriteFile(filepath.Join(directory, filepath.Base(path)), data, mode)
	}, func(binary string, args ...string) (string, error) {
		commands = append(commands, binary+" "+strings.Join(args, " "))
		return "ok", nil
	})
	if err != nil {
		t.Fatal(err)
	}
	timer, err := os.ReadFile(filepath.Join(directory, "olswpanel-whitelist.timer"))
	if err != nil {
		t.Fatal(err)
	}
	service, err := os.ReadFile(filepath.Join(directory, "olswpanel-whitelist.service"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(timer), "Requires=olswpanel-whitelist.service") || !strings.Contains(string(timer), "Unit=olswpanel-whitelist.service\n") || !strings.Contains(string(timer), "OnCalendar=Mon *-*-* 04:00:00\n") || !strings.Contains(string(timer), "Persistent=true\n") {
		t.Fatal("timer must trigger the service only on its schedule or a missed run", string(timer))
	}
	if !strings.Contains(string(service), "Type=oneshot\n") || !strings.Contains(string(service), "--refresh-whitelist --config=/www/ols-wpanel/config.json") || strings.Contains(string(service), "RemainAfterExit") {
		t.Fatal("recurring oneshot contract changed", string(service))
	}
	if !reflect.DeepEqual(commands, []string{"systemctl daemon-reload", "systemctl enable olswpanel-whitelist.timer", "systemctl start olswpanel-whitelist.timer"}) {
		t.Fatal("unexpected scheduler commands", commands)
	}
}

func TestWhitelistTimerInstallationPropagatesWriteAndSystemdFailures(t *testing.T) {
	for _, failure := range []string{"timer-write", "service-write", "daemon-reload", "enable", "start"} {
		t.Run(failure, func(t *testing.T) {
			writes, commands := 0, 0
			err := deployWhitelistTimer(func(path string, _ []byte, _ os.FileMode) error {
				writes++
				if failure == "timer-write" && strings.HasSuffix(path, ".timer") || failure == "service-write" && strings.HasSuffix(path, ".service") {
					return errors.New("injected unit write failure")
				}
				return nil
			}, func(_ string, args ...string) (string, error) {
				commands++
				if args[0] == failure {
					return "", errors.New("injected systemd failure")
				}
				return "", nil
			})
			if err == nil {
				t.Fatal("failed timer install claimed success")
			}
			if strings.HasSuffix(failure, "write") && commands != 0 {
				t.Fatal("systemd started with incomplete unit files")
			}
			wantCommands := map[string]int{"timer-write": 0, "service-write": 0, "daemon-reload": 1, "enable": 2, "start": 3}[failure]
			if commands != wantCommands || writes < 1 {
				t.Fatal("continued installation after failure", writes, commands)
			}
		})
	}
}
