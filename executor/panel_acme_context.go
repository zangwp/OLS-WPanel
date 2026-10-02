package executor

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func panelACMEContext(root string) string {
	return fmt.Sprintf("\ncontext /.well-known/acme-challenge/ {\n  location               %s/.well-known/acme-challenge/\n  allowBrowse            1\n  autoIndex              0\n  addDefaultCharset      off\n}\n", filepath.ToSlash(root))
}

// Existing managed default hosts deny all requests. Add only the ACME path,
// leaving the catch-all blocked. This runs before the panel accepts requests.
func EnsurePanelACMEContext() error {
	paths := currentOLSRuntimePaths()
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
	if strings.Contains(content, "context /.well-known/acme-challenge/") {
		return nil
	}
	if !strings.Contains(content, "vhDomain                ols-wpanel.invalid") || !strings.Contains(content, filepath.ToSlash(root)) {
		return fmt.Errorf("custom default virtual-host configuration requires manual ACME routing")
	}
	if err = writeOLSFileAtomic(path, []byte(content+panelACMEContext(root)), info.Mode().Perm()); err != nil {
		return err
	}
	rollback := func(cause error) error {
		if err := writeOLSFileAtomic(path, data, info.Mode().Perm()); err != nil {
			return fmt.Errorf("%w; default-host rollback failed: %v", cause, err)
		}
		return cause
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
