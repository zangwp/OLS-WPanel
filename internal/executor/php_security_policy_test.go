package executor

import (
	"strings"
	"testing"
)

func TestSitePHPOpenBaseDir(t *testing.T) {
	got := sitePHPOpenBaseDir("/www/wwwroot/example.com", "example.com")
	want := "/www/wwwroot/example.com:/tmp:/usr/share/php:/var/ols-wpanel/site-secrets/example.com"
	if got != want {
		t.Fatalf("sitePHPOpenBaseDir() = %q, want %q", got, want)
	}
}

func TestSitePHPDisabledFunctions(t *testing.T) {
	want := "exec,passthru,shell_exec,system,proc_open,popen,show_source"
	if got := sitePHPDisabledFunctions(); got != want {
		t.Fatalf("sitePHPDisabledFunctions() = %q, want %q", got, want)
	}
}

func TestSitePHPRunnerOpenBaseDir(t *testing.T) {
	got := sitePHPRunnerOpenBaseDir(
		"/www/wwwroot/example.com",
		"example.com",
		"/var/ols-wpanel/runners/wp-inventory/0123456789abcdef",
	)
	want := "/www/wwwroot/example.com:/tmp:/usr/share/php:/var/ols-wpanel/site-secrets/example.com:/var/ols-wpanel/runners/wp-inventory/0123456789abcdef"
	if got != want {
		t.Fatalf("sitePHPRunnerOpenBaseDir() = %q, want %q", got, want)
	}
}

func TestRenderOLSVHostUsesSharedSecurityPolicy(t *testing.T) {
	rendered, err := renderOLSVHostConfig(&OLSVHostData{
		Domain: "example.com", SystemUser: "wp_example",
		WebRoot: "/www/wwwroot/example.com", LogDir: "/www/wwwlogs/example.com",
		PHPProxy: "unix:/tmp/lshttpd/example.sock", TemplateVer: "v1.0", SiteType: "wordpress",
	})
	if err != nil {
		t.Fatalf("render OpenLiteSpeed vhost: %v", err)
	}

	wantLines := []string{
		"php_admin_value open_basedir \"" + sitePHPOpenBaseDir("/www/wwwroot/example.com", "example.com") + ":/www/wwwlogs/example.com\"",
		"php_admin_value disable_functions \"" + sitePHPDisabledFunctions() + "\"",
		"php_admin_flag allow_url_include Off",
	}
	for _, line := range wantLines {
		if count := strings.Count(rendered, line); count != 1 {
			t.Fatalf("rendered vhost contains %q %d times, want exactly once:\n%s", line, count, rendered)
		}
	}
	if strings.Contains(rendered, "%!") {
		t.Fatalf("rendered vhost contains a template formatting error:\n%s", rendered)
	}
}
