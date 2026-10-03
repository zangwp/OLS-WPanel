package executor

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestQueueMigrationRestoreAndVerificationRollback(t *testing.T) {
	for _, failVerification := range []bool{false, true} {
		t.Run(map[bool]string{false: "restore", true: "rollback"}[failVerification], func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "queue.conf")
			baseline := filepath.Join(dir, "baseline.json")
			installer := filepath.Join(dir, "installer.conf")
			legacy := "# OLS WPanel — 网络与内核优化\nnet.core.somaxconn = 65535\nnet.ipv4.tcp_max_syn_backlog = 8192\nnet.core.default_qdisc = fq\n"
			if err := os.WriteFile(installer, []byte(legacy), 0644); err != nil {
				t.Fatal(err)
			}
			live := map[string]string{vpsTuningKeys[0]: "65535", vpsTuningKeys[1]: "8192"}
			applied := false
			run := func(_ context.Context, _ string, args ...string) (string, error) {
				switch args[0] {
				case "-n":
					if failVerification && applied {
						return "123", nil
					}
					return live[args[1]], nil
				case "-p":
					data, err := os.ReadFile(args[1])
					if err != nil {
						return "", err
					}
					for _, line := range strings.Split(string(data), "\n") {
						if k, v, ok := strings.Cut(line, " = "); ok {
							live[k] = v
						}
					}
					applied = true
				case "-w":
					k, v, _ := strings.Cut(args[1], "=")
					live[k] = v
				default:
					t.Fatalf("unexpected args: %v", args)
				}
				return "", nil
			}
			_, err := setVPSTuningAt(context.Background(), "balanced", path, baseline, installer, run)
			data, readErr := os.ReadFile(installer)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if failVerification {
				if err == nil || string(data) != legacy || live[vpsTuningKeys[0]] != "65535" || live[vpsTuningKeys[1]] != "8192" {
					t.Fatalf("rollback failed: %v %s %v", err, data, live)
				}
				if _, err := os.Stat(path); !os.IsNotExist(err) {
					t.Fatal("failed config persisted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(data), "somaxconn") || !strings.Contains(string(data), "default_qdisc = fq") {
				t.Fatalf("bad migration: %s", data)
			}
			if _, err = setVPSTuningAt(context.Background(), "default", path, baseline, installer, run); err != nil {
				t.Fatal(err)
			}
			data, err = os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(data), "somaxconn = 65535") || live[vpsTuningKeys[0]] != "65535" {
				t.Fatal("restore did not persist original values")
			}
			if _, err = os.Stat(baseline); !os.IsNotExist(err) {
				t.Fatal("restore left stale baseline")
			}
		})
	}
}

func TestQueueMigrationRejectsUnownedFile(t *testing.T) {
	if _, err := stripInstallerQueues([]byte("# administrator\nnet.core.somaxconn = 100\n")); err == nil {
		t.Fatal("accepted administrator config")
	}
}

func TestVPSIPPriorityRoundTripPreservesAdministratorSettings(t *testing.T) {
	original := "# administrator comment\nlabel ::1/128 0\n"
	ipv4, err := buildVPSIPPriority(original, "ipv4")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ipv4, "precedence ::ffff:0:0/96 100") {
		t.Fatal("missing IPv4 priority")
	}
	ipv6, err := buildVPSIPPriority(ipv4, "ipv6")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(ipv6, ipPriorityBegin) != 1 || !strings.Contains(ipv6, "precedence ::/0 100") {
		t.Fatal("duplicated priority or missing IPv6 rule")
	}
	restored, err := buildVPSIPPriority(ipv6, "default")
	if err != nil || restored != original {
		t.Fatalf("restored %q, %v", restored, err)
	}
}
func TestVPSIPPriorityRejectsCustomRulesAndInvalidModes(t *testing.T) {
	if _, err := buildVPSIPPriority("precedence ::/0 80\n", "ipv4"); err == nil {
		t.Fatal("overrode administrator rule")
	}
	if _, err := buildVPSIPPriority("", "ipv4; reboot"); err == nil {
		t.Fatal("accepted command input")
	}
	if _, err := buildVPSIPPriority(ipPriorityBegin+"\nbroken", "default"); err == nil {
		t.Fatal("accepted incomplete managed block")
	}
	block := ipPriorityBegin + "\nprecedence ::ffff:0:0/96 100\n" + ipPriorityEnd + "\n"
	for _, content := range []string{block + block, ipPriorityBegin + "\n" + block} {
		for _, mode := range []string{"default", "ipv4", "ipv6"} {
			if _, err := buildVPSIPPriority(content, mode); err == nil {
				t.Fatalf("accepted duplicate/nested ownership markers for %s", mode)
			}
		}
	}
	original := "precedence ::/0 40\n" + block
	restored, err := buildVPSIPPriority(original, "default")
	if err != nil || restored != "precedence ::/0 40\n" {
		t.Fatalf("removing panel rules changed administrator rules: %q, %v", restored, err)
	}
}
