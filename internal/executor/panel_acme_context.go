package executor

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/zangwp/OLS-WPanel/internal/config"
)

var panelACMERouteMu sync.Mutex

func panelACMEContext(root string) string {
	return fmt.Sprintf("\ncontext /.well-known/acme-challenge/ {\n  location               %s/.well-known/acme-challenge/\n  allowBrowse            1\n  autoIndex              0\n  addDefaultCharset      off\n}\n", filepath.ToSlash(root))
}

// Existing managed default hosts deny all requests. Add only the ACME path,
// leaving the catch-all blocked. This runs before the panel accepts requests.
func EnsurePanelACMEContext() error {
	panelACMERouteMu.Lock()
	defer panelACMERouteMu.Unlock()
	return ensurePanelACMEContextAt(currentOLSRuntimePaths())
}

// Use the webroot that the managed HTTP listener actually maps to this
// hostname. A hostname already assigned to a website must not be hijacked by
// the panel; its existing redirects and ACME rules remain untouched.
func panelACMERootForDomain(domain string) (string, error) {
	panelACMERouteMu.Lock()
	defer panelACMERouteMu.Unlock()
	return panelACMERootAt(currentOLSRuntimePaths(), domain)
}

func panelACMERootAt(paths olsRuntimePaths, domain string) (string, error) {
	info, err := os.Lstat(paths.managed)
	if err != nil || !info.Mode().IsRegular() {
		return "", fmt.Errorf("managed HTTP registry unavailable")
	}
	data, err := os.ReadFile(paths.managed)
	if err != nil {
		return "", err
	}
	if !strings.HasPrefix(string(data), "# OLS WPanel managed OpenLiteSpeed registry.") {
		return "", fmt.Errorf("custom HTTP registry requires manual ACME routing")
	}
	configs := make(map[string]string)
	currentVHost, httpListener, mappedHost := "", false, ""
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 0 || strings.HasPrefix(fields[0], "#") {
			continue
		}
		switch fields[0] {
		case "virtualHost":
			if len(fields) == 3 && fields[2] == "{" {
				currentVHost = fields[1]
			}
		case "configFile":
			if currentVHost != "" && len(fields) == 2 {
				configs[currentVHost] = fields[1]
			}
		case "listener":
			httpListener = len(fields) == 3 && fields[1] == "OLSWPanelHTTP" && fields[2] == "{"
		case "map":
			if !httpListener || len(fields) != 3 {
				continue
			}
			for _, mappedDomain := range strings.Split(fields[2], ",") {
				if strings.EqualFold(mappedDomain, domain) {
					if mappedHost != "" {
						return "", fmt.Errorf("ambiguous HTTP hostname mapping")
					}
					mappedHost = fields[1]
				}
			}
		case "}":
			currentVHost, httpListener = "", false
		}
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	if mappedHost == "" || mappedHost == olsDefaultVHostName {
		if err := ensurePanelACMEContextAt(paths); err != nil {
			return "", err
		}
		root, _ := olsDefaultVHostPaths(paths)
		return root, nil
	}
	path := filepath.FromSlash(configs[mappedHost])
	available := filepath.Join(paths.root, "conf", "sites-available")
	if config.AppConfig != nil && strings.TrimSpace(config.AppConfig.Paths.OLSVHostsAvailable) != "" {
		available = config.AppConfig.Paths.OLSVHostsAvailable
	}
	if _, err := managedSubpath(available, path, "OpenLiteSpeed virtual-host configuration"); err != nil {
		return "", err
	}
	info, err = os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return "", fmt.Errorf("unsafe mapped virtual-host configuration")
	}
	data, err = os.ReadFile(path)
	if err != nil {
		return "", err
	}
	meta, err := parseOLSVHostMetadata(string(data), path)
	if err != nil || meta.name != mappedHost {
		return "", fmt.Errorf("mapped virtual-host metadata unavailable")
	}
	for _, mappedDomain := range meta.domains {
		if strings.EqualFold(mappedDomain, domain) {
			return meta.vhRoot, nil
		}
	}
	return "", fmt.Errorf("mapped virtual-host domain metadata differs")
}

func ensurePanelACMEContextAt(paths olsRuntimePaths) error {
	root, path := olsDefaultVHostPaths(paths)
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("unsafe default virtual-host configuration")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	content := string(data)
	legacyRoot := filepath.Join(filepath.Dir(paths.managed), "default-vhost-root")
	legacy := strings.Contains(content, filepath.ToSlash(legacyRoot))
	if !strings.Contains(content, "vhDomain                ols-wpanel.invalid") || (!strings.Contains(content, filepath.ToSlash(root)) && !legacy) {
		return fmt.Errorf("custom default virtual-host configuration requires manual ACME routing")
	}
	if err := ensurePanelACMEPublicRoot(paths); err != nil {
		return err
	}
	// Repair existing installations too: an already-written context does not
	// imply its directory exists (older installers only created the webroot).
	if err := ensurePanelACMEChallengeDirectory(root); err != nil {
		return err
	}
	registry, registryMode, registryChanged := []byte(nil), os.FileMode(0), false
	migratedRegistry := ""
	if legacy {
		if info, err := os.Lstat(paths.managed); err != nil || !info.Mode().IsRegular() {
			return fmt.Errorf("unsafe managed registry during default-host migration")
		} else {
			registryMode = info.Mode().Perm()
		}
		registry, err = os.ReadFile(paths.managed)
		if err != nil {
			return err
		}
		migrated, err := migratePanelACMERegistryRoot(string(registry), legacyRoot, root)
		if err != nil {
			return err
		}
		registryChanged = migrated != string(registry)
		migratedRegistry = migrated
		content = strings.ReplaceAll(content, filepath.ToSlash(legacyRoot), filepath.ToSlash(root))
	}
	if strings.Contains(content, "context /.well-known/acme-challenge/") {
		if !strings.Contains(content, panelACMEContext(root)) {
			return fmt.Errorf("custom ACME context requires manual routing")
		}
	} else {
		content += panelACMEContext(root)
	}
	rollback := func(cause error) error {
		var failures []string
		if err := writeOLSFileAtomic(path, data, info.Mode().Perm()); err != nil {
			failures = append(failures, fmt.Sprintf("default-host rollback failed: %v", err))
		}
		if registryChanged {
			if err := writeOLSFileAtomic(paths.managed, registry, registryMode); err != nil {
				failures = append(failures, fmt.Sprintf("registry rollback failed: %v", err))
			}
		}
		if len(failures) > 0 {
			return fmt.Errorf("%w; ACME rollback incomplete: %s", cause, strings.Join(failures, "; "))
		}
		return cause
	}
	if content == string(data) && !registryChanged {
		return nil
	}
	if registryChanged {
		if err := writeOLSFileAtomic(paths.managed, []byte(migratedRegistry), registryMode); err != nil {
			return rollback(err)
		}
	}
	if err = writeOLSFileAtomic(path, []byte(content), info.Mode().Perm()); err != nil {
		return rollback(err)
	}
	if out, err := runOLSCommand(paths.binary, "-t"); err != nil {
		return rollback(fmt.Errorf("OLS validation failed: %s", out))
	}
	if _, err := runOLSCommand("systemctl", "is-active", "--quiet", "lshttpd"); err != nil {
		return nil
	}
	if out, err := runOLSCommand("systemctl", "restart", "lshttpd"); err != nil {
		cause := rollback(fmt.Errorf("OLS restart failed: %s", out))
		if _, restoreErr := runOLSCommand("systemctl", "restart", "lshttpd"); restoreErr != nil {
			return fmt.Errorf("%w; OLS recovery failed: %v", cause, restoreErr)
		}
		return cause
	}
	return nil
}

func ensurePanelACMEPublicRoot(paths olsRuntimePaths) error {
	if !filepath.IsAbs(paths.root) {
		return fmt.Errorf("OpenLiteSpeed root must be absolute")
	}
	root, _ := olsDefaultVHostPaths(paths)
	// Only create the public static subtree. Never relax permissions on the
	// configuration directory or follow a replacement html/webroot symlink.
	for _, dir := range []string{paths.root, filepath.Join(paths.root, "html"), root} {
		info, err := os.Lstat(dir)
		if os.IsNotExist(err) && dir != paths.root {
			if err = os.Mkdir(dir, 0755); err != nil {
				return err
			}
			// Service umasks may be restrictive. These freshly created public
			// directories contain only static challenge files, not configuration.
			if err = os.Chmod(dir, 0755); err != nil {
				return err
			}
			continue
		}
		if err != nil {
			return err
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("unsafe public ACME directory")
		}
		if dir == root {
			if err := os.Chmod(dir, 0755); err != nil {
				return err
			}
		}
	}
	return nil
}

func migratePanelACMERegistryRoot(content, oldRoot, newRoot string) (string, error) {
	if !strings.HasPrefix(content, "# OLS WPanel managed OpenLiteSpeed registry.") {
		return "", fmt.Errorf("custom registry requires manual ACME routing")
	}
	lines := strings.SplitAfter(content, "\n")
	inside, updated := false, false
	for i, line := range lines {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if fields[0] == "virtualHost" {
			inside = len(fields) == 3 && fields[1] == olsDefaultVHostName && fields[2] == "{"
		} else if fields[0] == "}" {
			inside = false
		} else if inside && fields[0] == "vhRoot" {
			if updated || len(fields) != 2 || (strings.TrimSuffix(fields[1], "/") != filepath.ToSlash(oldRoot) && strings.TrimSuffix(fields[1], "/") != filepath.ToSlash(newRoot)) {
				return "", fmt.Errorf("custom default-host registry root requires manual routing")
			}
			lines[i] = strings.Replace(line, fields[1], filepath.ToSlash(newRoot)+"/", 1)
			updated = true
		}
	}
	if !updated {
		return "", fmt.Errorf("default-host registry mapping unavailable")
	}
	return strings.Join(lines, ""), nil
}
