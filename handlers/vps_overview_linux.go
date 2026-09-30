//go:build linux

package handlers

import (
	"context"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/zangwp/OLS-WPanel/executor"
)

func collectVPSOverview() VPSOverview {
	hostname, _ := os.Hostname()
	osInfo := readKeyValueFile("/etc/os-release", "=")
	osName := strings.TrimSpace(osInfo["PRETTY_NAME"])
	if osName == "" {
		osName = strings.TrimSpace(osInfo["NAME"] + " " + osInfo["VERSION_ID"])
	}

	services := make([]VPSService, 0, 6)
	for _, service := range []struct{ name, unit string }{
		{"OLS WPanel", "ols-wpanel"},
		{"OpenLiteSpeed", "lshttpd"},
		{"MariaDB", "mariadb"},
		{"Redis", "redis-server"},
		{"nftables", "nftables"},
		{"Fail2ban", "fail2ban"},
	} {
		services = append(services, VPSService{
			Name:    service.name,
			Unit:    service.unit,
			Active:  systemctlState("is-active", service.unit),
			Enabled: systemctlState("is-enabled", service.unit),
		})
	}

	swapStatus, _ := executor.GetSwapStatus()
	return VPSOverview{
		Identity: VPSIdentity{
			Hostname:       fallback(hostname, "unknown"),
			OS:             fallback(osName, "Linux"),
			Kernel:         fallback(runHostCommand("uname", "-r"), "unknown"),
			Architecture:   runtime.GOARCH,
			CPUModel:       fallback(readCPUModel(), "unknown"),
			CPUCores:       runtime.NumCPU(),
			Virtualization: fallback(runHostCommand("systemd-detect-virt"), "none"),
		},
		Stats: collectCurrentStats(),
		Tuning: VPSTuning{
			CongestionControl: fallback(readOneLine("/proc/sys/net/ipv4/tcp_congestion_control"), "unknown"),
			DefaultQDisc:      fallback(readOneLine("/proc/sys/net/core/default_qdisc"), "unknown"),
			Nameservers:       readNameservers(),
			Timezone:          readTimezone(),
			NTPSynchronized:   runHostCommand("timedatectl", "show", "--property=NTPSynchronized", "--value") == "yes",
			RebootRequired:    regularFileExists("/var/run/reboot-required"),
		},
		Services: services,
		Swap:     swapStatus,
		DNS:      executor.GetDNSStatus(),
	}
}

func readKeyValueFile(path, separator string) map[string]string {
	result := map[string]string{}
	data, err := os.ReadFile(path)
	if err != nil {
		return result
	}
	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.SplitN(strings.TrimSpace(line), separator, 2)
		if len(parts) != 2 {
			continue
		}
		value := strings.TrimSpace(parts[1])
		if unquoted, err := strconv.Unquote(value); err == nil {
			value = unquoted
		}
		result[strings.TrimSpace(parts[0])] = value
	}
	return result
}

func readCPUModel() string {
	data, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		if key == "model name" || key == "Hardware" || key == "Processor" {
			return strings.TrimSpace(parts[1])
		}
	}
	return ""
}

func readNameservers() []string {
	data, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return []string{}
	}
	seen := map[string]bool{}
	result := []string{}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 || fields[0] != "nameserver" || seen[fields[1]] {
			continue
		}
		seen[fields[1]] = true
		result = append(result, fields[1])
		if len(result) == 4 {
			break
		}
	}
	return result
}

func readTimezone() string {
	if value := readOneLine("/etc/timezone"); value != "" {
		return value
	}
	if value := runHostCommand("timedatectl", "show", "--property=Timezone", "--value"); value != "" {
		return value
	}
	return "unknown"
}

func readOneLine(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(strings.SplitN(string(data), "\n", 2)[0])
}

func runHostCommand(name string, args ...string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	output, _ := hostCommandContext(ctx, name, args...).CombinedOutput()
	return strings.TrimSpace(string(output))
}

func systemctlState(operation, unit string) string {
	state := strings.SplitN(runHostCommand("systemctl", operation, unit), "\n", 2)[0]
	if state == "" {
		return "unknown"
	}
	return state
}

func fallback(value, replacement string) string {
	if strings.TrimSpace(value) == "" {
		return replacement
	}
	return strings.TrimSpace(value)
}

func regularFileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}
