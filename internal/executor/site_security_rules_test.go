package executor

import (
	"regexp"
	"strings"
	"testing"
)

func TestOLSSensitiveFilesPreservePublicPaths(t *testing.T) {
	tests := []struct {
		path string
		deny bool
	}{
		{"/.env", true}, {"/.env.production", true}, {"/app/.env.local", true},
		{"/.git/config", true}, {"/.svn/entries", true}, {"/.htaccess", true},
		{"/.user.ini", true}, {"/wp-config.php", true}, {"/wp-config.php.bak", true},
		{"/wp-config.php~", true}, {"/composer.lock", true}, {"/auth.json", true},
		{"/config.php.bak", true}, {"/dump.sql.gz", true}, {"/secrets.yaml", true},
		{"/.well-known/acme-challenge/token", false}, {"/.well-known/security.txt", false},
		{"/wp-content/uploads/guide.zip", false}, {"/download/report.sql", false},
		{"/config.php", false}, {"/posts/wp-config.php-explained", false},
		{"/environment", false}, {"/.environment", false}, {"/index.php", false},
	}
	patterns := make([]*regexp.Regexp, 0, len(olsSensitivePathPatterns))
	for _, pattern := range olsSensitivePathPatterns {
		patterns = append(patterns, regexp.MustCompile("(?i)"+pattern))
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			denied := false
			for _, pattern := range patterns {
				denied = denied || pattern.MatchString(tt.path)
			}
			if denied != tt.deny {
				t.Fatalf("sensitive path %q denied=%v, want %v", tt.path, denied, tt.deny)
			}
		})
	}
}

func TestOLSXMLRPCAndUploadsPHPPathsAreScoped(t *testing.T) {
	for _, tt := range []struct {
		pattern, path string
		deny          bool
	}{
		{olsXMLRPCPathPattern, "/xmlrpc.php", true},
		{olsXMLRPCPathPattern, "/XMLRPC.php/path-info", true},
		{olsXMLRPCPathPattern, "/xmlrpc.php.jpg", false},
		{olsXMLRPCPathPattern, "/posts/xmlrpc.php", false},
		{olsXMLRPCPathPattern, "/wp-json/", false},
		{olsUploadsPHPPattern, "/wp-content/uploads/2026/shell.php", true},
		{olsUploadsPHPPattern, "/wp-content/uploads/shell.PHP/path-info", true},
		{olsUploadsPHPPattern, "/wp-content/uploads/shell.phtml", true},
		{olsUploadsPHPPattern, "/wp-content/uploads/shell.php8", true},
		{olsUploadsPHPPattern, "/wp-content/uploads/image.php.jpg", false},
		{olsUploadsPHPPattern, "/wp-content/plugins/plugin/run.php", false},
		{olsUploadsPHPPattern, "/wp-admin/admin-ajax.php", false},
	} {
		if got := regexp.MustCompile("(?i)" + tt.pattern).MatchString(tt.path); got != tt.deny {
			t.Errorf("pattern=%q path=%q denied=%v, want %v", tt.pattern, tt.path, got, tt.deny)
		}
	}
}

func TestOLSSQLiQueryPatternsRequireStrongSignals(t *testing.T) {
	patterns := make([]*regexp.Regexp, 0, len(olsSQLiQueryPatterns))
	for _, pattern := range olsSQLiQueryPatterns {
		patterns = append(patterns, regexp.MustCompile("(?i)"+pattern))
	}
	for _, tt := range []struct {
		query string
		deny  bool
	}{
		{"id=1%20UNION%20SELECT%201,2%20FROM%20users", true},
		{"id=1+UNION+ALL+SELECT+1+FROM+users", true},
		{"id=1/**/UNION/**/SELECT/**/1/**/FROM/**/users", true},
		{"id=1%20AND%20SLEEP%285%29", true},
		{"id=(select(pg_sleep(5)))", true},
		{"id=benchmark%281000%2cmd5%281%29%29", true},
		{"id=1%3BDROP%20TABLE%20users", true},
		{"id=1%27%20OR%201=1%20--", true},
		{"id=load_file%28%27/etc/passwd%27%29", true},
		{"id=1+into+outfile+%27tmp/file%27", true},
		{"id=1+select+table_name+from+information_schema.tables", true},
		{"order=update", false}, {"q=information_schema", false},
		{"q=union+select", false}, {"q=unionized+selection+from+users", false},
		{"q=asleep%285%29", false}, {"id=1&id2=select", false},
		{"id=1%2520UNION%2520SELECT%25201%2520FROM%2520users", false},
	} {
		t.Run(tt.query, func(t *testing.T) {
			denied := false
			for _, pattern := range patterns {
				denied = denied || pattern.MatchString(tt.query)
			}
			if denied != tt.deny {
				t.Fatalf("SQLi query %q denied=%v, want %v", tt.query, denied, tt.deny)
			}
		})
	}
}

func TestOLSSecurityRulesRespectWordPressAndSQLiSettings(t *testing.T) {
	for _, tt := range []struct {
		name, siteType     string
		xmlrpc, block, ban bool
	}{
		{"wordpress default", "wordpress", false, true, true},
		{"xmlrpc allowed", "wordpress", true, true, false},
		{"SQLi disabled", "wordpress", false, false, true},
		{"generic PHP", "php", false, true, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			data := &OLSVHostData{SiteType: tt.siteType, XMLRPCEnabled: tt.xmlrpc, SQLiBlockEnabled: tt.block, SQLiAutoBanLog: tt.ban}
			rules := olsSiteSecurityRewriteRules(data)
			wordpress := tt.siteType == "wordpress"
			if got := strings.Contains(rules, "E=OLS_WPANEL_SECURITY:xmlrpc"); got != (wordpress && !tt.xmlrpc) {
				t.Fatalf("XML-RPC rule present=%v", got)
			}
			if got := strings.Contains(rules, "E=OLS_WPANEL_SECURITY:uploads_php"); got != wordpress {
				t.Fatalf("uploads PHP rule present=%v", got)
			}
			if got := strings.Contains(rules, "E=OLS_WPANEL_SECURITY:sqli"); got != (wordpress && tt.block) {
				t.Fatalf("SQLi rule present=%v", got)
			}
			if got := strings.Contains(rules, "E=OLS_WPANEL_SECURITY:sqli,E=OLS_WPANEL_SQLI_AUTOBAN:1"); got != (wordpress && tt.block && tt.ban) {
				t.Fatalf("SQLi automatic-ban marker present=%v", got)
			}
			if !strings.Contains(rules, "E=OLS_WPANEL_SECURITY:sensitive") {
				t.Fatal("sensitive-file protection must remain enabled")
			}
		})
	}
}
