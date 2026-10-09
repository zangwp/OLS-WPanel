package executor

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"

	"github.com/zangwp/OLS-WPanel/internal/config"
	"github.com/zangwp/OLS-WPanel/internal/models"
)

var liteSpeedPanelConstants = map[string]string{
	"LITESPEED_CONF__OBJECT": "object", "LITESPEED_CONF__OBJECT__KIND": "object-kind",
	"LITESPEED_CONF__OBJECT__HOST": "object-host", "LITESPEED_CONF__OBJECT__PORT": "object-port",
	"LITESPEED_CONF__OBJECT__DB_ID": "object-db_id", "LITESPEED_CONF__OBJECT__PERSISTENT": "object-persistent",
}

func liteSpeedConfigMigration(content string) (string, map[string]any, error) {
	patch := map[string]any{}
	// A setting-specific constant is inert unless LiteSpeed's master switch is
	// enabled. Copying inert values into the database would activate settings
	// that the administrator never enabled. Only migrate a literal, unambiguous
	// master declaration; the runner also checks its actual runtime value.
	master := regexp.MustCompile(`(?m)^\s*define\s*\(\s*(?:'LITESPEED_CONF'|"LITESPEED_CONF")\s*,\s*(true|false)\s*\)\s*;`)
	masters := master.FindAllStringSubmatch(content, -1)
	if len(masters) > 1 {
		return "", nil, fmt.Errorf("duplicate cache override: LITESPEED_CONF")
	}
	if len(masters) == 0 {
		if regexp.MustCompile(`(?m)^\s*define\s*\(\s*['"]LITESPEED_CONF['"]`).MatchString(content) {
			return "", nil, fmt.Errorf("unsupported cache override: LITESPEED_CONF")
		}
		return content, patch, nil
	}
	if masters[0][1] != "true" {
		return content, patch, nil
	}
	for name, key := range liteSpeedPanelConstants {
		re := regexp.MustCompile(`(?m)^\s*define\s*\(\s*['"]` + regexp.QuoteMeta(name) + `['"]\s*,\s*(true|false|[0-9]+|'[^'\r\n]*'|"[^"\r\n]*")\s*\)\s*;`)
		match := re.FindStringSubmatch(content)
		if len(match) == 0 {
			declared := regexp.MustCompile(`(?m)^\s*define\s*\(\s*['"]` + regexp.QuoteMeta(name) + `['"]`)
			if declared.MatchString(content) {
				return "", nil, fmt.Errorf("unsupported cache override: %s", name)
			}
			continue
		}
		if len(re.FindAllString(content, -1)) != 1 {
			return "", nil, fmt.Errorf("duplicate cache override: %s", name)
		}
		value := match[1]
		switch value {
		case "true":
			patch[key] = true
		case "false":
			patch[key] = false
		default:
			if value[0] == '\'' || value[0] == '"' {
				if strings.Contains(value, "\\") || (value[0] == '"' && strings.Contains(value, "$")) {
					return "", nil, fmt.Errorf("unsupported cache string: %s", name)
				}
				patch[key] = value[1 : len(value)-1]
			} else {
				n, err := strconv.Atoi(value)
				if err != nil {
					return "", nil, err
				}
				patch[key] = n
			}
		}
		content = re.ReplaceAllString(content, "")
	}
	// Preserve unrelated administrator-owned LiteSpeed override constants.
	if !regexp.MustCompile(`LITESPEED_CONF__`).MatchString(content) {
		content = removeConstant(content, "LITESPEED_CONF")
	}
	return content, patch, nil
}

// LiteSpeed's save API may reconcile WP_CACHE while persisting object-cache
// settings. Accept only the exact insertion/removal emitted by v7.9.1's
// Activation::manage_wp_cache_const; any other wp-config edit remains a conflict.
// Reapply the same migration to the current file so that a legitimate WP_CACHE
// reconciliation is retained instead of overwriting it with the earlier bytes.
func liteSpeedConfigAfterMigration(before, current []byte, patch map[string]any) ([]byte, error) {
	if !liteSpeedWPConfigSaveChange(before, current) {
		return nil, errWPConfigChanged
	}
	next, currentPatch, err := liteSpeedConfigMigration(string(current))
	if err != nil || !reflect.DeepEqual(patch, currentPatch) {
		return nil, errWPConfigChanged
	}
	return []byte(next), nil
}

func liteSpeedWPConfigSaveChange(before, current []byte) bool {
	if bytes.Equal(before, current) {
		return true
	}
	// Deliberately narrower than the plugin's word-value expression: dynamic
	// definitions cannot be proven safe from source text and remain conflicts.
	cache := regexp.MustCompile(`define\(\s*(?:'WP_CACHE'|"WP_CACHE")\s*,\s*(true|false)\s*\)\s*;`)
	if len(cache.FindAll(before, -1)) > 1 {
		return false
	}
	without := cache.ReplaceAll(before, nil)
	if !bytes.Equal(before, without) && bytes.Equal(without, current) {
		return true
	}
	if !bytes.HasPrefix(without, []byte("<?php")) {
		return false
	}
	enabled := append([]byte("<?php\ndefine( 'WP_CACHE', true );"), without[len("<?php"):]...)
	return bytes.Equal(enabled, current)
}

// The caller owns the shared site-operation lock. Persist the effective values
// first; remove overrides only after the isolated runner verifies the write.
func MigrateLiteSpeedCacheSettings(ctx context.Context, cfg *config.Config, site *models.Website) error {
	if site == nil || site.SiteType != "wordpress" || site.FileLockEnabled {
		return fmt.Errorf("unlock the WordPress site before cache migration")
	}
	path := filepath.Join(site.WebRoot, "wp-config.php")
	before, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	_, patch, err := liteSpeedConfigMigration(string(before))
	if err != nil {
		return err
	}
	if len(patch) == 0 {
		return nil
	}
	runner, err := NewWPInventoryRunner()
	if err != nil {
		return err
	}
	runner.cacheSettings = patch
	if _, err = runner.Collect(ctx, cfg, site, false); err != nil {
		return fmt.Errorf("cache settings migration failed; overrides retained: %w", err)
	}
	current, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	next, err := liteSpeedConfigAfterMigration(before, current, patch)
	if err != nil {
		return err
	}
	return writeWPConfig(path, next)
}
