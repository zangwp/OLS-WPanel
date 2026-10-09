package executor

import (
	"errors"
	"strings"
	"testing"
)

func TestCacheMigrationPreservesEffectiveSettings(t *testing.T) {
	content := `<?php
 define('LITESPEED_CONF', true);
 define('LITESPEED_CONF__OBJECT', false);
 define('LITESPEED_CONF__OBJECT__HOST', '127.0.0.1');
 define('LITESPEED_CONF__OBJECT__PORT', 6379);
 define('LITESPEED_CONF__CACHE', true);
 define('LSOC_PREFIX', 'site_');`
	next, patch, err := liteSpeedConfigMigration(content)
	if err != nil {
		t.Fatal(err)
	}
	if patch["object"] != false || patch["object-port"] != 6379 || patch["object-host"] != "127.0.0.1" {
		t.Fatalf("changed effective settings: %#v", patch)
	}
	if strings.Contains(next, "LITESPEED_CONF__OBJECT") || !strings.Contains(next, "LITESPEED_CONF__CACHE") || !strings.Contains(next, "LSOC_PREFIX") {
		t.Fatal("incorrect ownership migration")
	}
}
func TestCacheMigrationRejectsExpression(t *testing.T) {
	if _, _, err := liteSpeedConfigMigration("define('LITESPEED_CONF', true);\ndefine('LITESPEED_CONF__OBJECT', getenv('CACHE'));"); err == nil {
		t.Fatal("expression silently ignored")
	}
}

func TestCacheMigrationDoesNotActivateInactiveOverrides(t *testing.T) {
	for _, master := range []string{"", "define('LITESPEED_CONF', false);\n"} {
		t.Run(master, func(t *testing.T) {
			content := "<?php\n" + master + "define('LITESPEED_CONF__OBJECT', true);\ndefine('LITESPEED_CONF__OBJECT__KIND', true);\n"
			next, patch, err := liteSpeedConfigMigration(content)
			if err != nil || next != content || len(patch) != 0 {
				t.Fatalf("inactive override was migrated: next=%q patch=%#v err=%v", next, patch, err)
			}
		})
	}
}

func TestCacheMigrationRejectsAmbiguousMasterSwitch(t *testing.T) {
	for _, master := range []string{
		"define('LITESPEED_CONF', getenv('CACHE'));",
		"define('LITESPEED_CONF', true);\ndefine('LITESPEED_CONF', false);",
	} {
		if _, _, err := liteSpeedConfigMigration("<?php\n" + master + "\ndefine('LITESPEED_CONF__OBJECT', true);"); err == nil {
			t.Fatalf("ambiguous master accepted: %s", master)
		}
	}
}

func TestCacheMigrationPreservesOfficialWPReconciliation(t *testing.T) {
	base := "<?php\ndefine('LITESPEED_CONF', true);\ndefine('LITESPEED_CONF__OBJECT', true);\ndefine('LITESPEED_CONF__OBJECT__HOST', 'localhost');\ndefine('DB_NAME', 'wordpress');\n"
	for _, tc := range []struct {
		name    string
		before  string
		current string
		cache   string
	}{
		{"unchanged", base, base, ""},
		{"insert", base, strings.Replace(base, "<?php", "<?php\ndefine( 'WP_CACHE', true );", 1), "define( 'WP_CACHE', true );"},
		{"existing_true", base + "define('WP_CACHE', true);\n", base + "define('WP_CACHE', true);\n", "define('WP_CACHE', true);"},
		{"existing_false", base + "define('WP_CACHE', false);\n", base + "define('WP_CACHE', false);\n", "define('WP_CACHE', false);"},
		{"enable_existing", base + "define('WP_CACHE', false);\n", strings.Replace(base, "<?php", "<?php\ndefine( 'WP_CACHE', true );", 1) + "\n", "define( 'WP_CACHE', true );"},
		{"disable_existing", base + "define('WP_CACHE', true);\n", base + "\n", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, patch, err := liteSpeedConfigMigration(tc.before)
			if err != nil {
				t.Fatal(err)
			}
			next, err := liteSpeedConfigAfterMigration([]byte(tc.before), []byte(tc.current), patch)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(next), "LITESPEED_CONF") || !strings.Contains(string(next), "define('DB_NAME', 'wordpress');") {
				t.Fatalf("incorrect migrated file: %q", next)
			}
			if tc.cache == "" {
				if strings.Contains(string(next), "WP_CACHE") {
					t.Fatalf("unexpected WP_CACHE: %q", next)
				}
			} else if !strings.Contains(string(next), tc.cache) {
				t.Fatalf("discarded official WP_CACHE reconciliation: %q", next)
			}
		})
	}
}

func TestCacheMigrationRejectsOtherConcurrentConfigEdits(t *testing.T) {
	before := "<?php\ndefine('LITESPEED_CONF', true);\ndefine('LITESPEED_CONF__OBJECT', true);\ndefine('DB_NAME', 'wordpress');\n"
	_, patch, err := liteSpeedConfigMigration(before)
	if err != nil {
		t.Fatal(err)
	}
	enabled := strings.Replace(before, "<?php", "<?php\ndefine( 'WP_CACHE', true );", 1)
	for _, tc := range []struct{ name, current string }{
		{"database", strings.Replace(before, "'wordpress'", "'other_database'", 1)},
		{"comment", before + "// concurrent administrator edit\n"},
		{"override", strings.Replace(before, "OBJECT', true", "OBJECT', false", 1)},
		{"master", strings.Replace(before, "CONF', true", "CONF', false", 1)},
		{"cache_and_database", strings.Replace(enabled, "'wordpress'", "'other_database'", 1)},
		{"noncanonical_cache", strings.Replace(before, "<?php", "<?php\ndefine('WP_CACHE', false);", 1)},
		{"dynamic_cache", strings.Replace(before, "<?php", "<?php\ndefine('WP_CACHE', getenv('CACHE'));", 1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := liteSpeedConfigAfterMigration([]byte(before), []byte(tc.current), patch); !errors.Is(err, errWPConfigChanged) {
				t.Fatalf("concurrent edit accepted: %q err=%v", tc.current, err)
			}
		})
	}
}

func TestCacheMigrationRejectsDuplicateOrDynamicWPChanges(t *testing.T) {
	base := "<?php\ndefine('LITESPEED_CONF', true);\ndefine('LITESPEED_CONF__OBJECT', true);\n"
	for _, before := range []string{
		base + "define('WP_CACHE', false);\ndefine('WP_CACHE', false);\n",
		base + "define('WP_CACHE', CUSTOM_CACHE);\n",
	} {
		_, patch, err := liteSpeedConfigMigration(before)
		if err != nil {
			t.Fatal(err)
		}
		current := strings.Replace(base, "<?php", "<?php\ndefine( 'WP_CACHE', true );", 1) + "\n"
		if _, err := liteSpeedConfigAfterMigration([]byte(before), []byte(current), patch); !errors.Is(err, errWPConfigChanged) {
			t.Fatalf("unprovable WP_CACHE reconciliation accepted: %q err=%v", before, err)
		}
	}
}
