package executor

import (
	_ "embed"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
)

//go:embed panel_cli.sh
var panelCommandScript string

const (
	panelCommandMarker = "# OLS WPanel CLI — o"
)

// EnsurePanelCommands installs the short lowercase and uppercase CLI entry
// points. Because these are generic one-character names, existing paths are
// replaced only when they already carry OLS WPanel's exact ownership marker.
func EnsurePanelCommands() {
	paths := []string{"/usr/local/bin/o", "/usr/local/bin/O"}
	if err := ensurePanelCommandsAt(paths...); err != nil {
		log.Printf("安装面板 o/O 命令失败: %v", err)
	}
}

func ensurePanelCommandsAt(paths ...string) error {
	if len(paths) == 0 {
		return fmt.Errorf("no panel command paths supplied")
	}
	for _, path := range paths {
		replaceable, err := managedCommandPathReplaceable(path, panelCommandMarker)
		if err != nil {
			return fmt.Errorf("inspect %s: %w", path, err)
		}
		if !replaceable {
			return fmt.Errorf("refusing to replace non-OLS command at %s", path)
		}
	}
	for _, path := range paths {
		if err := writeFileAtomic(path, []byte(panelCommandScript), 0755); err != nil {
			return fmt.Errorf("install %s: %w", path, err)
		}
	}
	return nil
}

func managedCommandPathReplaceable(path, marker string) (bool, error) {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	if !info.Mode().IsRegular() {
		return false, nil
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	lines := strings.SplitN(string(content), "\n", 6)
	for i := 0; i < len(lines) && i < 5; i++ {
		if lines[i] == marker {
			return true, nil
		}
	}
	return false, nil
}

// writeFileAtomic writes data to path via a temp file + rename in the same
// directory, so a concurrent reader (e.g. someone running o mid-upgrade)
// never observes a partially-written script.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".ols-wpanel-cli-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpPath, perm); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}
