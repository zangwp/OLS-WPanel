package tests

import (
	"path"
	"regexp"
	"strings"
	"testing"
)

func TestInstallACMEPublicRootPreservesDefaultIsolation(t *testing.T) {
	script := readInstallScript(t, installScriptPath)
	assignment := regexp.MustCompile(`(?m)^OLS_DEFAULT_ROOT="([^"]+)"$`).FindStringSubmatch(script)
	if len(assignment) != 2 || !path.IsAbs(assignment[1]) {
		t.Fatal("default ACME root must be an absolute public directory")
	}
	root := path.Clean(assignment[1])
	if strings.HasPrefix(root+"/", "/usr/local/lsws/conf/") {
		t.Fatal("HTTP workers cannot read challenges through the private configuration directory")
	}
	heredoc := func(marker string) string {
		t.Helper()
		start := requiredIndex(t, script, "<< '"+marker+"'\n") + len("<< '"+marker+"'\n")
		end := requiredIndex(t, script[start:], "\n"+marker)
		return script[start : start+end]
	}
	vhost, registry := heredoc("OLSDEFAULTVHOSTEOF"), heredoc("OLSMANAGEDEOF")
	field := func(content, key string) string {
		t.Helper()
		match := regexp.MustCompile(`(?m)^\s*` + regexp.QuoteMeta(key) + `\s+(\S+)\s*$`).FindStringSubmatch(content)
		if len(match) != 2 {
			t.Fatalf("missing configuration field %s", key)
		}
		return strings.TrimSuffix(match[1], "/")
	}
	if field(vhost, "docRoot") != root || field(registry, "vhRoot") != root {
		t.Fatal("restrained virtual host and document roots must both point to the public challenge subtree")
	}
	for key, want := range map[string]string{"restrained": "1", "enableScript": "0", "allowSymbolLink": "0"} {
		if field(registry, key) != want {
			t.Errorf("default virtual-host isolation %s must remain %s", key, want)
		}
	}
	for _, tc := range []struct{ context, location, browse string }{
		{"/", root, "0"},
		{"/.well-known/acme-challenge/", root + "/.well-known/acme-challenge", "1"},
	} {
		pattern := `(?s)context\s+` + regexp.QuoteMeta(tc.context) + `\s*\{([^}]+)\}`
		match := regexp.MustCompile(pattern).FindStringSubmatch(vhost)
		if len(match) != 2 || field(match[1], "location") != tc.location || field(match[1], "allowBrowse") != tc.browse {
			t.Fatalf("context %s must retain the intended static access boundary", tc.context)
		}
	}
}
