package handlers

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/zangwp/OLS-WPanel/executor"
)

func TestFindPHPIniValueSkipsComments(t *testing.T) {
	content := "; memory_limit = 128M\n# memory_limit = 192M\nmemory_limit = 256M\n"
	if got := findPHPIniValue(content, "memory_limit"); got != "256M" {
		t.Fatalf("findPHPIniValue() = %q, want 256M", got)
	}
}

func TestParseMariaDBVersionUsesDistributionVersion(t *testing.T) {
	input := "mariadb from 11.8.3-MariaDB, client 15.2 for debian-linux-gnu (x86_64) using EditLine wrapper"
	if got := parseMariaDBVersion(input); got != "11.8.3-MariaDB" {
		t.Fatalf("parseMariaDBVersion() = %q, want 11.8.3-MariaDB", got)
	}
	input = "mariadb  Ver 15.1 Distrib 10.11.13-MariaDB, for debian-linux-gnu (x86_64) using EditLine wrapper"
	if got := parseMariaDBVersion(input); got != "10.11.13-MariaDB" {
		t.Fatalf("parseMariaDBVersion() = %q, want 10.11.13-MariaDB", got)
	}
}

func TestParseOpenLiteSpeedVersion(t *testing.T) {
	input := "LiteSpeed/1.9.2 Open (BUILD built: Tue Aug 25 15:48:28 UTC 2026)"
	if got := parseOpenLiteSpeedVersion(input); got != "1.9.2" {
		t.Fatalf("parseOpenLiteSpeedVersion() = %q, want 1.9.2", got)
	}
}

func TestParseAptCandidateVersion(t *testing.T) {
	input := "openlitespeed:\n  Installed: 1.9.2-1\n  Candidate: 1.9.3-1\n"
	if got := parseAptCandidateVersion(input); got != "1.9.3-1" {
		t.Fatalf("parseAptCandidateVersion() = %q, want 1.9.3-1", got)
	}
}

func TestOpenLiteSpeedRuntimeDetails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "httpd_config.conf")
	content := "disableWebAdmin 1\nenableGzipCompress 1\nenableDynGzipCompress 1\nenableBrCompress 4\nquicEnable 1\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	details := openLiteSpeedRuntimeDetails("zh-CN", path)
	if len(details) != 4 {
		t.Fatalf("details length = %d, want 4", len(details))
	}
	for i := 0; i < 3; i++ {
		if details[i].Tone != "success" || details[i].Value != "已启用" {
			t.Fatalf("detail %d = %+v, want enabled/success", i, details[i])
		}
	}
	if details[3].Value != "已禁用（由面板管理）" || details[3].Tone != "info" {
		t.Fatalf("webadmin detail = %+v", details[3])
	}
}

func TestPHPConfigRequiresVHostRegeneration(t *testing.T) {
	if !phpConfigRequiresVHostRegeneration("post_max_size") {
		t.Fatal("post_max_size should regenerate OpenLiteSpeed vhosts")
	}
	if phpConfigRequiresVHostRegeneration("max_input_vars") {
		t.Fatal("max_input_vars should only restart OpenLiteSpeed")
	}
	// OPcache 参数只存在于全局 ini，改动只需要重启 OpenLiteSpeed，
	// 不应该触发全站点虚拟主机批量重建。
	for _, key := range []string{"opcache.memory_consumption", "opcache.max_accelerated_files"} {
		if phpConfigRequiresVHostRegeneration(key) {
			t.Fatalf("%s should only restart OpenLiteSpeed, not regenerate vhosts", key)
		}
	}
}

// TestAdaptiveConfigFallbackMatchesRecommendFormula 确认 opcache 两项的展示兜底值
// 不是写死的固定数字，而是复用跟"重新计算推荐值"按钮相同的公式现算出来的——避免
// 两处出现不一致的数字造成困惑（代码审核发现的问题）。
func TestAdaptiveConfigFallbackMatchesRecommendFormula(t *testing.T) {
	facts := executor.CollectSystemFacts()
	wantMem := strconv.Itoa(executor.RecommendOPcacheMemoryConsumptionMB(facts))
	wantFiles := strconv.Itoa(executor.RecommendOPcacheMaxAcceleratedFiles(facts))

	if got := adaptiveConfigFallback("opcache.memory_consumption"); got != wantMem {
		t.Fatalf("adaptiveConfigFallback(opcache.memory_consumption) = %q, want %q", got, wantMem)
	}
	if got := adaptiveConfigFallback("opcache.max_accelerated_files"); got != wantFiles {
		t.Fatalf("adaptiveConfigFallback(opcache.max_accelerated_files) = %q, want %q", got, wantFiles)
	}
	if got := adaptiveConfigFallback("memory_limit"); got != "" {
		t.Fatalf("adaptiveConfigFallback(memory_limit) should be empty (static key), got %q", got)
	}
	if _, ok := configDefaults["opcache.memory_consumption"]; ok {
		t.Fatal("opcache.memory_consumption should no longer have a static fallback in configDefaults")
	}
}

func TestOpcacheKeysAreWhitelistedAndIntegerValidated(t *testing.T) {
	for _, key := range []string{"opcache.memory_consumption", "opcache.max_accelerated_files"} {
		if !softConfigAllowed["PHP"][key] {
			t.Fatalf("%s should be in the PHP config whitelist", key)
		}
		if msg := validateSoftwareConfigValue("zh-CN", "PHP", key, "256"); msg != "" {
			t.Fatalf("expected %s=256 to be valid, got error: %s", key, msg)
		}
		if msg := validateSoftwareConfigValue("zh-CN", "PHP", key, "not-a-number"); msg == "" {
			t.Fatalf("expected %s=not-a-number to be rejected", key)
		}
	}
}
