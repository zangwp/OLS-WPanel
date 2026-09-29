package handlers

import "testing"

func TestParseSystemPackageCatalogUsesSupportedDistribution(t *testing.T) {
	tests := []struct {
		name         string
		osRelease    string
		distribution string
		baseURL      string
	}{
		{
			name:         "debian 13",
			osRelease:    "ID=debian\nVERSION_ID=\"13\"\nVERSION_CODENAME=trixie\n",
			distribution: "Debian 13",
			baseURL:      "https://packages.debian.org/trixie/",
		},
		{
			name:         "ubuntu 24.04",
			osRelease:    "ID=ubuntu\nVERSION_ID='24.04'\nVERSION_CODENAME=noble\n",
			distribution: "Ubuntu 24.04 LTS",
			baseURL:      "https://packages.ubuntu.com/noble/",
		},
		{
			name:         "ubuntu 26.04",
			osRelease:    "ID=ubuntu\nVERSION_ID=26.04\nVERSION_CODENAME=resolute\n",
			distribution: "Ubuntu 26.04 LTS",
			baseURL:      "https://packages.ubuntu.com/resolute/",
		},
		{
			name:      "unsupported release stays unlinked",
			osRelease: "ID=ubuntu\nVERSION_ID=25.10\nVERSION_CODENAME=questing\n",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := parseSystemPackageCatalog(test.osRelease)
			if got.Distribution != test.distribution || got.BaseURL != test.baseURL {
				t.Fatalf("catalog = %+v, want distribution=%q base=%q", got, test.distribution, test.baseURL)
			}
		})
	}
}

func TestParseUpgradablePackages(t *testing.T) {
	input := "Listing...\nopenlitespeed/stable 1.9.3-1 amd64 [upgradable from: 1.9.2-1]\nlibssl3/noble-security 3.0.13-0ubuntu3.5 amd64 [upgradable from: 3.0.13-0ubuntu3.4]\n"
	got := parseUpgradablePackages(input)
	if len(got) != 2 {
		t.Fatalf("package count = %d, want 2", len(got))
	}
	if got[0].Name != "openlitespeed" || got[0].Repo != "stable" || got[0].Version != "1.9.3-1" {
		t.Fatalf("first package = %+v", got[0])
	}
	if got[1].Name != "libssl3" || got[1].Repo != "noble-security" {
		t.Fatalf("second package = %+v", got[1])
	}
}
