package executor

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

var ErrLSPHPPackageVersionMismatch = errors.New("LSPHP runtime and extension package versions do not match")

// LSPHPPackageVersionMismatchError contains package identities only. It never
// includes raw PHP startup output or administrator configuration contents.
type LSPHPPackageVersionMismatchError struct {
	Branch         string
	Package        string
	RuntimeVersion string
	PackageVersion string
}

func (err *LSPHPPackageVersionMismatchError) Error() string {
	return fmt.Sprintf("LSPHP %s package %s (%s) does not match runtime package %s; update this PHP branch and its bundled extensions together", err.Branch, err.Package, err.PackageVersion, err.RuntimeVersion)
}

func (err *LSPHPPackageVersionMismatchError) Unwrap() error {
	return ErrLSPHPPackageVersionMismatch
}

var lsphpBundledPackageVersionRE = regexp.MustCompile(`^(?:[0-9]+:)?(8\.[345]\.[0-9]+)(?:-[0-9A-Za-z.+:~\-]+)?$`)

func lsphpPackageBranch(name string) string {
	name, _, _ = strings.Cut(name, ":")
	for _, branch := range []string{"83", "84", "85"} {
		if name == "lsphp"+branch || strings.HasPrefix(name, "lsphp"+branch+"-") {
			return branch
		}
	}
	return ""
}

func lsphpBundledPackage(name, branch string) bool {
	prefix := "lsphp" + branch
	if name == prefix {
		return true
	}
	// These packages are built from LiteSpeed's php8.x source package. PECL
	// packages such as Redis, igbinary and Imagick have independent versions.
	for _, suffix := range []string{"common", "mysql", "curl", "intl", "opcache"} {
		if name == prefix+"-"+suffix {
			return true
		}
	}
	return false
}

func lsphpPackageMismatch(branch, name, runtimeVersion, packageVersion string) error {
	safeVersion := func(version string) string {
		if len(version) == 0 || len(version) > 128 || !backupDependencyPackageVersionRE.MatchString(version) {
			return "unverified"
		}
		return version
	}
	return &LSPHPPackageVersionMismatchError{
		Branch: branch[:1] + "." + branch[1:], Package: name,
		RuntimeVersion: safeVersion(runtimeVersion), PackageVersion: safeVersion(packageVersion),
	}
}

// validateLSPHPPackageVersions adds the compatibility constraint missing from
// LiteSpeed's loose Debian dependencies. For example, PHP 8.3.36 OPcache refers
// to zend_handle_delayed_oom, which an installed 8.3.35 runtime does not export.
// A successful new-only APT simulation alone therefore cannot prove that a new
// bundled module is compatible with the frozen runtime.
func validateLSPHPPackageVersions(installed, planned map[string]string, requested []string) error {
	branches := map[string]string{}
	for _, name := range requested {
		if branch := lsphpPackageBranch(name); branch != "" {
			branches[branch] = branch
		}
	}
	for _, branch := range backupDependencySortedPackages(branches) {
		versions := map[string]string{}
		for _, packages := range []map[string]string{installed, planned} {
			for _, name := range backupDependencySortedPackages(packages) {
				base, _, _ := strings.Cut(name, ":")
				if !lsphpBundledPackage(base, branch) {
					continue
				}
				if previous, found := versions[base]; found && previous != packages[name] {
					return lsphpPackageMismatch(branch, base, previous, packages[name])
				}
				versions[base] = packages[name]
			}
		}
		core := "lsphp" + branch
		coreVersion := versions[core]
		if coreVersion == "" {
			// A partial/new branch may acquire its core in the APT plan. The
			// completed plan must contain that core before any bundled module
			// can be installed, even if the vendor omitted the dependency.
			if planned != nil && len(versions) > 0 {
				return lsphpPackageMismatch(branch, backupDependencySortedPackages(versions)[0], "", versions[backupDependencySortedPackages(versions)[0]])
			}
			continue
		}
		coreRelease := lsphpBundledPackageVersionRE.FindStringSubmatch(coreVersion)
		if coreRelease == nil || !strings.HasPrefix(coreRelease[1], branch[:1]+"."+branch[1:]+".") {
			return lsphpPackageMismatch(branch, core, coreVersion, coreVersion)
		}
		for _, name := range backupDependencySortedPackages(versions) {
			version := versions[name]
			release := lsphpBundledPackageVersionRE.FindStringSubmatch(version)
			if release == nil || release[1] != coreRelease[1] {
				return lsphpPackageMismatch(branch, name, coreVersion, version)
			}
			// common is Architecture: all. The vendor legitimately publishes
			// common 8.3.36-2 with amd64 runtime/modules 8.3.36-1, so its Debian
			// revision may differ while the upstream PHP patch must still match.
			if name != core+"-common" && version != coreVersion {
				return lsphpPackageMismatch(branch, name, coreVersion, version)
			}
		}
	}
	return nil
}
