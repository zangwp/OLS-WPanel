package executor

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Recovery is limited to missing units on panel-managed installations. Existing
// native units (including deliberately stopped ones) and custom aliases remain untouched.
func EnsureOpenLiteSpeedServiceRegistration() error {
	if data, err := os.ReadFile("/www/ols-wpanel/guard_paused.json"); err == nil {
		var paused map[string]bool
		if err := json.Unmarshal(data, &paused); err != nil {
			return fmt.Errorf("cannot read service pause state: %w", err)
		}
		if paused["lshttpd"] || paused["lsws"] {
			return nil
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	return restoreOLSServiceRegistration("/etc/systemd/system", "/usr/local/lsws/admin/misc/lshttpd.service", func(name string, args ...string) ([]byte, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		return exec.CommandContext(ctx, name, args...).CombinedOutput()
	})
}

func restoreOLSServiceRegistration(root, vendor string, command func(string, ...string) ([]byte, error)) (result error) {
	run := func(name string, args ...string) (string, error) {
		out, err := command(name, args...)
		if err != nil {
			return "", fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
		}
		return strings.TrimSpace(string(out)), nil
	}
	policy, err := os.ReadFile(filepath.Join(root, "lshttpd.service.d", "ols-wpanel.conf"))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if string(policy) != managedOLSServiceDropInContent && string(policy) != managedServiceDropInBoundedContent && string(policy) != managedServiceDropInFixedContent && string(policy) != managedServiceDropInLegacyContent {
		return nil
	}
	fragment, err := run("systemctl", "show", "lshttpd.service", "--property=FragmentPath", "--value")
	if err != nil {
		return err
	}
	if fragment != "" {
		if _, err := os.Stat(fragment); err == nil {
			return nil
		}
	}
	target := filepath.Join(root, "lshttpd.service")
	alias := filepath.Join(root, "lsws.service")
	if _, err := os.Lstat(target); !os.IsNotExist(err) {
		return fmt.Errorf("refusing to replace existing or inaccessible OLS service: %s", target)
	}
	aliasExists := false
	if info, err := os.Lstat(alias); err == nil {
		link, linkErr := os.Readlink(alias)
		if info.Mode()&os.ModeSymlink == 0 || linkErr != nil || (link != "lshttpd.service" && link != target) {
			return fmt.Errorf("custom lsws service conflicts with OLS recovery")
		}
		aliasExists = true
	} else if !os.IsNotExist(err) {
		return err
	}
	legacy, err := run("systemctl", "show", "lsws.service", "--property=FragmentPath", "--value")
	if err != nil {
		return err
	}
	generated := legacy == "/run/systemd/generator/lsws.service" || legacy == "/run/systemd/generator.late/lsws.service" || legacy == "/run/systemd/generator.early/lsws.service"
	if legacy != "" && !generated && !aliasExists {
		return fmt.Errorf("custom lsws service conflicts with OLS recovery: %s", legacy)
	}
	info, err := os.Lstat(vendor)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("OLS vendor service is not a regular file")
	}
	content, err := os.ReadFile(vendor)
	if err != nil {
		return err
	}
	if !strings.Contains(string(content), "/usr/local/lsws/bin/lswsctrl start") {
		return fmt.Errorf("unrecognized OLS vendor service")
	}
	if _, err := run("/usr/local/lsws/bin/openlitespeed", "-t"); err != nil {
		return err
	}
	// Prepare the native definition before stopping the legacy daemon. Never overwrite.
	f, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		return err
	}
	_, writeErr := f.Write(content)
	closeErr := f.Close()
	// If registration fails, remove only files created by this attempt and restore
	// the generated legacy service so an alias failure cannot strand a running site.
	aliasCreated := false
	legacyStopped := false
	defer func() {
		if result == nil {
			return
		}
		if current, err := os.ReadFile(target); err == nil && string(current) == string(content) {
			if err := os.Remove(target); err != nil {
				result = fmt.Errorf("%w; cleanup failed: %v", result, err)
				return
			}
		}
		if aliasCreated {
			_ = os.Remove(alias)
		}
		if _, err := run("systemctl", "daemon-reload"); err != nil {
			result = fmt.Errorf("%w; rollback reload failed: %v", result, err)
			return
		}
		if legacyStopped {
			if _, err := run("systemctl", "enable", "lsws.service"); err != nil {
				result = fmt.Errorf("%w; legacy enable failed: %v", result, err)
			}
			if _, err := run("systemctl", "start", "lsws.service"); err != nil {
				result = fmt.Errorf("%w; legacy recovery failed: %v", result, err)
			}
		}
	}()
	if writeErr != nil {
		return writeErr
	}
	if closeErr != nil {
		return closeErr
	}
	if generated {
		legacyStopped = true
		if _, err := run("systemctl", "stop", "lsws.service"); err != nil {
			return err
		}
		if _, err := run("systemctl", "disable", "lsws.service"); err != nil {
			return err
		}
	}
	if !aliasExists {
		if err := os.Symlink("lshttpd.service", alias); err != nil {
			return err
		}
		aliasCreated = true
	}
	for _, args := range [][]string{{"daemon-reload"}, {"reset-failed", "lshttpd.service"}, {"enable", "--now", "lshttpd.service"}, {"is-active", "--quiet", "lshttpd.service"}} {
		if _, err := run("systemctl", args...); err != nil {
			return err
		}
	}
	return nil
}
