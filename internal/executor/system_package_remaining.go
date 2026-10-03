package executor

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

const systemUpdateCommandTimeout = 2 * time.Minute

type SystemPackageCandidate struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Repo    string `json:"repo"`
}

func newSystemUpdateCommand(ctx context.Context) *exec.Cmd {
	cmd := exec.CommandContext(ctx, "apt", "list", "--upgradable")
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	return cmd
}

func readSystemPackageCandidateOutput(ctx context.Context) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, systemUpdateCommandTimeout)
	defer cancel()
	return newSystemUpdateCommand(ctx).Output()
}

// ReadSystemPackageCandidates shares the same local APT inventory between the
// update page, alerts, and the verification after an upgrade.
func ReadSystemPackageCandidates(ctx context.Context) ([]SystemPackageCandidate, error) {
	out, err := readSystemPackageCandidateOutput(ctx)
	if err != nil {
		return nil, fmt.Errorf("unable to check system updates: %w", err)
	}
	return ParseSystemPackageCandidates(string(out)), nil
}

// ParseSystemPackageCandidates accepts candidate rows rather than localized
// headings or diagnostic output. The command always runs in the C locale.
func ParseSystemPackageCandidates(output string) []SystemPackageCandidate {
	packages := []SystemPackageCandidate{}
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 || !strings.Contains(line, "[upgradable from:") {
			continue
		}
		name, repo, ok := strings.Cut(fields[0], "/")
		if ok && name != "" && repo != "" {
			packages = append(packages, SystemPackageCandidate{Name: name, Version: fields[1], Repo: repo})
		}
	}
	return packages
}

// Match APT's local candidate list after the upgrade, including packages held
// back by administrator policy. Never unhold packages or force their upgrade.
func readRemainingSystemPackages(ctx context.Context) ([]string, error) {
	packages, err := ReadSystemPackageCandidates(ctx)
	if err != nil {
		return nil, err
	}
	return formatRemainingSystemPackages(packages), nil
}

func parseRemainingSystemPackages(output string) []string {
	return formatRemainingSystemPackages(ParseSystemPackageCandidates(output))
}

func formatRemainingSystemPackages(packages []SystemPackageCandidate) []string {
	var remaining []string
	for _, pkg := range packages {
		remaining = append(remaining, pkg.Name+" → "+pkg.Version)
	}
	return remaining
}
