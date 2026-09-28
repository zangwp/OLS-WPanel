package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestDistributionLicenseAndNoticeAreComplete(t *testing.T) {
	license, err := os.ReadFile("LICENSE")
	if err != nil {
		t.Fatalf("read LICENSE: %v", err)
	}
	licenseText := string(license)
	if len(license) < 34000 {
		t.Fatalf("LICENSE is unexpectedly short: %d bytes", len(license))
	}
	for _, required := range []string{
		"GNU GENERAL PUBLIC LICENSE",
		"17. Interpretation of Sections 15 and 16.",
		"END OF TERMS AND CONDITIONS",
		"How to Apply These Terms to Your New Programs",
	} {
		if !strings.Contains(licenseText, required) {
			t.Errorf("LICENSE is missing %q", required)
		}
	}

	notice, err := os.ReadFile("NOTICE.md")
	if err != nil {
		t.Fatalf("read NOTICE.md: %v", err)
	}
	noticeText := string(notice)
	for _, required := range []string{"OLS WPanel", "GNU General Public License", "GPL-3.0-only", "zangwp", "Copyright (C) 2026"} {
		if !strings.Contains(noticeText, required) {
			t.Errorf("NOTICE.md is missing %q", required)
		}
	}

	thirdParty, err := os.ReadFile("THIRD_PARTY_NOTICES.md")
	if err != nil {
		t.Fatalf("read THIRD_PARTY_NOTICES.md: %v", err)
	}
	thirdPartyText := string(thirdParty)
	for _, required := range []string{"OLS WPanel Open Source License", "GPL-3.0-only", "OLS WPanel project notice"} {
		if !strings.Contains(thirdPartyText, required) {
			t.Errorf("THIRD_PARTY_NOTICES.md is missing %q", required)
		}
	}
}

func TestAllWorkflowActionsArePinnedToCommitSHAs(t *testing.T) {
	workflowPaths, err := filepath.Glob(".github/workflows/*.yml")
	if err != nil {
		t.Fatal(err)
	}
	if len(workflowPaths) == 0 {
		t.Fatal("no GitHub Actions workflows found")
	}
	actionRefPattern := regexp.MustCompile(`(?m)^\s*uses:\s+[^@\s]+@([^\s#]+)`)
	fullSHA := regexp.MustCompile(`^[0-9a-f]{40}$`)
	for _, path := range workflowPaths {
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		refs := actionRefPattern.FindAllStringSubmatch(string(content), -1)
		if len(refs) == 0 {
			t.Errorf("%s contains no pinned action references", path)
		}
		for _, ref := range refs {
			if !fullSHA.MatchString(ref[1]) {
				t.Errorf("%s contains an action not pinned to a full commit SHA: %q", path, ref[1])
			}
		}
	}
}

func TestLegacyDistributionNamesDoNotReturn(t *testing.T) {
	legacyNames := []string{
		"naiba" + "biji",
		"wp" + "-panel",
		"wp" + "_panel",
		"wp" + " panel",
		"wpp" + "anel",
		"wpp" + "_optimizer",
	}
	textExtensions := map[string]bool{
		".css": true, ".go": true, ".html": true, ".js": true,
		".json": true, ".md": true, ".php": true, ".sh": true,
		".txt": true, ".yaml": true, ".yml": true,
	}
	err := filepath.WalkDir(".", func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			base := filepath.Base(path)
			if path == ".git" || path == "scratch" || strings.HasPrefix(base, ".codex-go-") {
				return filepath.SkipDir
			}
			return nil
		}
		if !textExtensions[strings.ToLower(filepath.Ext(path))] {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Size() > 2<<20 {
			return nil
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		lowerContent := strings.ToLower(string(content))
		for _, legacyName := range legacyNames {
			if strings.Contains(lowerContent, legacyName) {
				t.Errorf("legacy distribution name %q found in %s", legacyName, path)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestInitialOLSDistributionBoundariesRemainExplicit(t *testing.T) {
	checks := map[string][]string{
		"README.md": {
			"Debian 13",
			"Ubuntu 24.04 LTS",
			"OpenLiteSpeed",
		},
		"README.en.md": {
			"OpenLiteSpeed",
			"LSPHP 8.3",
			"v1.0.2",
		},
		"docs/upgrade-compatibility.md": {
			"v1.0.0",
			"first OLS WPanel release",
			"Use a clean server",
			"/usr/local/bin/ols-wpanel",
		},
		"docs/verified-install.md": {
			"version='v1.0.2'",
			"install.sh.sha256.sig",
			"openssl pkeyutl -verify",
			"Do not replace the fixed release URL",
		},
	}
	for path, required := range checks {
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		for _, phrase := range required {
			if !strings.Contains(string(content), phrase) {
				t.Errorf("%s is missing the initial distribution boundary %q", path, phrase)
			}
		}
	}
}
