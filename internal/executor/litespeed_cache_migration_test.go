package executor

import (
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
	if _, _, err := liteSpeedConfigMigration("define('LITESPEED_CONF__OBJECT', getenv('CACHE'));"); err == nil {
		t.Fatal("expression silently ignored")
	}
}
