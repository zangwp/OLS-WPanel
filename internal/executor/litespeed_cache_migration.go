package executor

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
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
	next, patch, err := liteSpeedConfigMigration(string(before))
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
	if !bytes.Equal(before, current) {
		return errWPConfigChanged
	}
	return writeWPConfig(path, []byte(next))
}
