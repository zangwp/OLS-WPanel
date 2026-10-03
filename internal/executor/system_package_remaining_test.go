package executor

import (
	"context"
	"reflect"
	"strings"
	"testing"
)

func TestParseRemainingSystemPackages(t *testing.T) {
	output := "Listing...\nlinux-image-amd64/stable-security 6.12.111-1 amd64 [upgradable from: 6.12.107-1]\nheld-package/stable 2.0 amd64 [upgradable from: 1.0]\nWARNING: apt does not have a stable CLI interface.\n"
	want := []string{"linux-image-amd64 → 6.12.111-1", "held-package → 2.0"}
	if got := parseRemainingSystemPackages(output); !reflect.DeepEqual(got, want) {
		t.Fatalf("remaining updates = %#v, want %#v", got, want)
	}
	if got := parseRemainingSystemPackages("Listing...\n"); len(got) != 0 {
		t.Fatalf("expected no remaining updates, got %#v", got)
	}
}

func TestSystemPackageCandidatesIgnoreHeadingsAndDiagnostics(t *testing.T) {
	output := "正在列表... 完成\nListing... Done\nWARNING: apt does not have a stable CLI interface.\nN: See apt-secure(8) for repository https://example.com/repo\n" +
		"linux-image-amd64/stable-security,stable 6.12.111-1 amd64 [upgradable from: 6.12.107-1]\n" +
		"libssl3:amd64/noble-security\t3.0.13\tamd64 [upgradable from: 3.0.12]\n" +
		"installed-package/stable 1.0 amd64 [installed]\n"
	want := []SystemPackageCandidate{
		{Name: "linux-image-amd64", Version: "6.12.111-1", Repo: "stable-security,stable"},
		{Name: "libssl3:amd64", Version: "3.0.13", Repo: "noble-security"},
	}
	if got := ParseSystemPackageCandidates(output); !reflect.DeepEqual(got, want) {
		t.Fatalf("candidate inventory = %#v, want %#v", got, want)
	}
	if got := ParseSystemPackageCandidates("Listing...\n"); got == nil || len(got) != 0 {
		t.Fatalf("empty inventory must serialize as an empty list: %#v", got)
	}
}

func TestSystemPackageCommandFixesLocaleWithoutAShell(t *testing.T) {
	t.Setenv("LC_ALL", "zh_CN.UTF-8")
	cmd := newSystemUpdateCommand(context.Background())
	if got := strings.Join(cmd.Args, " "); got != "apt list --upgradable" {
		t.Fatalf("unexpected command: %s", got)
	}
	locale := ""
	for _, entry := range cmd.Env {
		if strings.HasPrefix(entry, "LC_ALL=") {
			locale = entry
		}
	}
	if locale != "LC_ALL=C" {
		t.Fatalf("APT inventory locale = %s", locale)
	}
}
