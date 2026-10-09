package executor

import (
	"fmt"
	"strings"
)

const (
	olsSiteSecurityBegin = "# BEGIN OLS-WPanel-Site-Security v1\n"
	olsSiteSecurityEnd   = "# END OLS-WPanel-Site-Security v1\n"
	olsSecurityLogFields = `peer=%{PROXY_REMOTE_ADDR}e ols_security="%{OLS_WPANEL_SECURITY}e" ols_autoban="%{OLS_WPANEL_SQLI_AUTOBAN}e"`
	olsXMLRPCPathPattern = `^/?xmlrpc\.php(?:/.*)?$`
	olsUploadsPHPPattern = `^/?wp-content/uploads/.*\.(?:php[0-9]*|phtml|pht|phar)(?:/.*)?$`
	olsSQLWhitespace     = `(?:\s|%20|\+|/\*[^*]{0,40}\*/)`
	olsSQLKeywordStart   = `(?:\b|%20|\+|/\*[^*]{0,40}\*/)`
)

// Restrict credentials and known backup names, rather than denying all archives
// or all dot directories. In particular, ACME's .well-known directory is public.
var olsSensitivePathPatterns = []string{
	`(?:^|/)\.(?:env(?:\.[^/]*)?|git(?:ignore|attributes|modules)?|svn|hg|bzr|htaccess(?:\.[^/]*)?|htpasswd(?:\.[^/]*)?|user\.ini(?:\.[^/]*)?|DS_Store)(?:/|$)`,
	`^/?(?:wp-config\.php(?:[.~][^/]*)?|composer\.(?:json|lock)|auth\.json|phpunit\.xml(?:\.dist)?|secrets\.(?:json|ya?ml))(?:/|$)`,
	`(?:^|/)(?:config(?:\.php)?|settings\.php)(?:\.(?:bak|old|orig|save|swp|txt)|~)(?:/|$)`,
	`^/?(?:backup|database|dump|db)(?:[-_.][^/]*)?\.(?:sql|sqlite3?|db)(?:\.(?:gz|bz2|xz|zip))?(?:/|$)`,
}

// These deliberately narrow PCRE expressions cover URL/query SQL probes, not
// request bodies, JSON, arbitrary encodings, or a complete SQL grammar. Bound
// repeats keep attacker-controlled input from creating unbounded backtracking.
var olsSQLiQueryPatterns = []string{
	olsSQLKeywordStart + `union` + olsSQLWhitespace + `{1,16}(?:all` + olsSQLWhitespace + `{1,16})?select` + olsSQLWhitespace + `{1,16}[^&]{1,1000}(?:` + olsSQLKeywordStart + `from` + olsSQLWhitespace + `{1,16}|` + olsSQLKeywordStart + `information_schema\b)`,
	olsSQLKeywordStart + `(?:sleep|pg_sleep)` + olsSQLWhitespace + `{0,16}(?:\(|%28)` + olsSQLWhitespace + `{0,16}[0-9]{1,9}` + olsSQLWhitespace + `{0,16}(?:\)|%29)`,
	olsSQLKeywordStart + `benchmark` + olsSQLWhitespace + `{0,16}(?:\(|%28)` + olsSQLWhitespace + `{0,16}[0-9]{1,9}` + olsSQLWhitespace + `{0,16}(?:,|%2c)`,
	olsSQLKeywordStart + `select` + olsSQLWhitespace + `{1,16}[^&]{1,1000}` + olsSQLKeywordStart + `information_schema\b`,
	olsSQLKeywordStart + `load_file` + olsSQLWhitespace + `{0,16}(?:\(|%28)` + olsSQLWhitespace + `{0,16}(?:'|%27)`,
	olsSQLKeywordStart + `into` + olsSQLWhitespace + `{1,16}outfile` + olsSQLWhitespace + `{1,16}(?:'|%27)`,
	`(?:;|%3b)` + olsSQLWhitespace + `{0,16}(?:drop|alter|truncate)` + olsSQLWhitespace + `{1,16}(?:table|database)` + olsSQLWhitespace + `{1,16}`,
	`(?:'|%27)` + olsSQLWhitespace + `{0,16}or` + olsSQLWhitespace + `{1,16}(?:'|%27)?[0-9]{1,9}(?:'|%27)?` + olsSQLWhitespace + `{0,16}(?:=|%3d)` + olsSQLWhitespace + `{0,16}(?:'|%27)?[0-9]{1,9}(?:'|%27)?` + olsSQLWhitespace + `{0,16}(?:--|%2d%2d|%23)`,
}

var loadOLSSQLiProtectionSettings = GetSQLiProtectionSettings

func olsSiteSecurityRewriteRules(data *OLSVHostData) string {
	if data == nil {
		return ""
	}
	var out strings.Builder
	out.WriteString(olsSiteSecurityBegin)
	// These are request environment variables, not similarly named HTTP headers.
	// Reset each request before any panel rule, including internal rewrites.
	out.WriteString("RewriteRule ^ - [E=OLS_WPANEL_SECURITY:-,E=OLS_WPANEL_SQLI_AUTOBAN:0,E=OLS_WPANEL_SQLI_SEARCH:0]\n")
	for _, pattern := range olsSensitivePathPatterns {
		writeOLSSecurityDenyRule(&out, pattern, "sensitive", false)
	}
	if data.SiteType == "wordpress" {
		if !data.XMLRPCEnabled {
			writeOLSSecurityDenyRule(&out, olsXMLRPCPathPattern, "xmlrpc", false)
		}
		writeOLSSecurityDenyRule(&out, olsUploadsPHPPattern, "uploads_php", false)
		if data.SQLiBlockEnabled {
			// A single core search parameter is data, even if a user searches for
			// SQL syntax. Any extra parameter prevents this narrow exemption.
			out.WriteString("RewriteCond %{QUERY_STRING} ^s=[^&]*$ [NC]\n")
			out.WriteString("RewriteRule ^/?(?:index\\.php)?$ - [E=OLS_WPANEL_SQLI_SEARCH:1]\n")
			out.WriteString("RewriteCond %{QUERY_STRING} ^search=[^&]*$ [NC]\n")
			out.WriteString("RewriteRule ^/?wp-json/wp/v2/(?:posts|pages)/?$ - [E=OLS_WPANEL_SQLI_SEARCH:1]\n")
			for _, pattern := range olsSQLiQueryPatterns {
				out.WriteString("RewriteCond %{ENV:OLS_WPANEL_SQLI_SEARCH} !=1\n")
				fmt.Fprintf(&out, "RewriteCond %%{QUERY_STRING} %s [NC]\n", pattern)
				writeOLSSecurityDenyRule(&out, "^", "sqli", data.SQLiAutoBanLog)
			}
		}
	}
	out.WriteString(olsSiteSecurityEnd)
	return out.String()
}

func writeOLSSecurityDenyRule(out *strings.Builder, pattern, reason string, autoBan bool) {
	ban := 0
	if autoBan {
		ban = 1
	}
	fmt.Fprintf(out, "RewriteRule %s - [F,L,NC,E=OLS_WPANEL_SECURITY:%s,E=OLS_WPANEL_SQLI_AUTOBAN:%d]\n", pattern, reason, ban)
}

// OLSVHostSecurityRulesMatch checks the complete generated rules and trusted log
// fields. Callers supply expected settings; this inspection never reads the DB.
// A marker comment or an ordinary application-generated HTTP 403 is insufficient.
func OLSVHostSecurityRulesMatch(content string, data *OLSVHostData) bool {
	if data == nil {
		return false
	}
	activeRules := "rewrite {\n  enable                 1\n  autoLoadHtaccess       1\n  rules                  <<<END_rules\n" + olsSiteSecurityRewriteRules(data)
	if !strings.Contains(content, activeRules) {
		return false
	}
	if data.SiteType != "wordpress" {
		return true
	}
	return strings.Contains(content, "accesslog ") &&
		strings.Contains(content, strings.ReplaceAll(olsSecurityLogFields, `"`, `\"`))
}
