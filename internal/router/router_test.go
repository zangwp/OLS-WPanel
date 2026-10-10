package router

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html"
	"html/template"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/zangwp/OLS-WPanel/internal/i18n"
)

var pageTemplates = map[string]string{
	"login.html":                  "",
	"dashboard.html":              "dashboard_content",
	"websites.html":               "websites_content",
	"wordpress_overview.html":     "wordpress_overview_content",
	"website_new.html":            "websites_new_content",
	"website_detail.html":         "websites_detail_content",
	"wordpress_site_detail.html":  "wordpress_site_detail_content",
	"databases.html":              "databases_content",
	"database_detail.html":        "database_detail_content",
	"ai_diagnostics.html":         "ai_diagnostics_content",
	"log_analysis.html":           "log_analysis_content",
	"cron.html":                   "cron_content",
	"backups.html":                "backups_content",
	"remote_backup_settings.html": "remote_backup_settings_content",
	"firewall.html":               "firewall_content",
	"files.html":                  "files_content",
	"security.html":               "security_content",
	"settings.html":               "settings_content",
	"alert.html":                  "alert_content",
	"software.html":               "software_content",
	"vps.html":                    "vps_content",
	"help.html":                   "help_content",
}

func TestPageTemplatesRender(t *testing.T) {
	for page, content := range pageTemplates {
		t.Run(page, func(t *testing.T) {
			if output := renderPage(t, page, content); len(output) == 0 {
				t.Fatalf("render %s: empty output", page)
			}
		})
	}
}

func TestLogAnalysisPageIncludesContent(t *testing.T) {
	output := renderPage(t, "log_analysis.html", "log_analysis_content")
	if !bytes.Contains(output, []byte(`x-data="logAnalysisPage()"`)) {
		t.Fatal("rendered log analysis page is missing its content template")
	}
}

func TestLogAnalysisExplainsServerTrafficMetrics(t *testing.T) {
	template, err := os.ReadFile("../../web/templates/log_analysis.html")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range [][]byte{
		[]byte(`log_analysis.requests_help`),
		[]byte(`log_analysis.unique_ips_help`),
		[]byte(`statusCount('444')`),
		[]byte(`identifiedBotRequests()`),
		[]byte(`log_analysis.traffic_explanation`),
	} {
		if !bytes.Contains(template, required) {
			t.Fatalf("log analysis traffic explanation missing %q", required)
		}
	}
	if bytes.Contains(template, []byte(`report.security_request_count`)) {
		t.Fatal("security log records must not be presented as the HTTP 444 rejection count")
	}
}

func TestLogAnalysisTrafficMetricCalculations(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is not available")
	}
	rendered := renderPage(t, "log_analysis.html", "log_analysis_content")
	scripts := regexp.MustCompile(`(?s)<script>(.*?)</script>`).FindAllSubmatch(rendered, -1)
	var pageScript []byte
	for _, script := range scripts {
		if bytes.Contains(script[1], []byte("function logAnalysisPage()")) {
			pageScript = script[1]
			break
		}
	}
	if len(pageScript) == 0 {
		t.Fatal("log analysis page script not found")
	}
	harness := []byte(`
function t(key, params = {}) { return key + '|' + JSON.stringify(params); }
const page = logAnalysisPage();
page.report = null;
if (page.statusCount('444') !== 0 || page.identifiedBotRequests() !== 0) throw new Error('null report fallback failed');
page.report = { access_requests: 20, unique_ips: 8, status_codes: null, bots: null };
if (page.statusCount('444') !== 0 || page.identifiedBotRequests() !== 0) throw new Error('null collection fallback failed');
if (page.categoryPercent(5) !== 25 || page.hasTrafficCategories()) throw new Error('legacy category fallback failed');
page.report = { access_requests: 0, classification_version: 1, traffic_categories: [] };
if (page.categoryPercent(5) !== 0 || !page.hasTrafficCategories()) throw new Error('empty classified report failed');
page.report = {
    access_requests: 20,
    unique_ips: 8,
    classification_version: 1,
    traffic_categories: [{ key: 'page_like', count: 5 }],
    status_codes: [{ name: '200', count: 12 }, { name: '444', count: 7 }],
    bots: [
        { verification: 'verified', count: 3 },
        { verification: 'fake', count: 2 },
        { verification: 'unverified', count: 4 },
        { verification: 'unknown', count: '5' }
    ]
};
if (page.statusCount('444') !== 7) throw new Error('HTTP 444 lookup failed');
if (page.identifiedBotRequests() !== 14) throw new Error('bot aggregation omitted a verification state');
if (page.categoryPercent(5) !== 25 || page.shareText(5) !== '25.0%') throw new Error('category percentage failed');
if (!page.hasTrafficCategories()) throw new Error('classified report was treated as legacy');
if (page.categoryLabel('page_like') !== 'log_analysis.category_page_like|{}') throw new Error('category label failed');
if (page.categoryColor('page_like') !== 'bg-green-500') throw new Error('category color failed');
const explanation = page.trafficExplanation();
for (const expected of ['"requests":20', '"ips":8', '"blocked":7', '"bots":14']) {
    if (!explanation.includes(expected)) throw new Error('traffic explanation missing ' + expected);
}
`)
	testScript := append(append([]byte{}, pageScript...), harness...)
	scriptPath := filepath.Join(t.TempDir(), "log-analysis-metrics.js")
	if err := os.WriteFile(scriptPath, testScript, 0600); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command(node, scriptPath).CombinedOutput(); err != nil {
		t.Fatalf("log analysis traffic metric behavior failed: %v\n%s", err, output)
	}
}

func TestAlertWebhookUsesConfigurationAsEnablement(t *testing.T) {
	page, err := os.ReadFile("../../web/templates/alert.html")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(page, []byte("webhook_enabled")) {
		t.Fatal("Webhook settings should not expose a separate enable flag")
	}
	for _, expected := range [][]byte{[]byte(`webhook_channel: 'wecom'`), []byte(`webhook_url: ''`), []byte(`api('/alert/settings', { method: 'PUT'`)} {
		if !bytes.Contains(page, expected) {
			t.Fatalf("Webhook settings are missing %q", expected)
		}
	}
}

func TestAlertLogKeepsMetadataColumnsReadable(t *testing.T) {
	page, err := os.ReadFile("../../web/templates/alert.html")
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range [][]byte{
		[]byte(`table-fixed w-full min-w-[860px]`),
		[]byte(`w-44 py-2 pr-3 text-left whitespace-nowrap`),
		[]byte(`class="py-2 pr-3 align-top text-sm text-gray-300" style="white-space: normal; overflow-wrap: anywhere;" x-text="typeLabel(l.alert_type)"`),
		[]byte(`py-2 whitespace-nowrap`),
		[]byte(`style="white-space: normal; overflow-wrap: anywhere;" x-text="l.message"`),
	} {
		if !bytes.Contains(page, expected) {
			t.Fatalf("alert log table is missing %q", expected)
		}
	}
	if bytes.Contains(page, []byte(`text-gray-300 whitespace-nowrap" x-text="typeLabel(l.alert_type)"`)) {
		t.Fatal("alert type must wrap inside its fixed column instead of overlapping the level column")
	}
}

func TestFeatureSettingsAreSeparatedFromPanelSettings(t *testing.T) {
	settings, err := os.ReadFile("../../web/templates/settings.html")
	if err != nil {
		t.Fatal(err)
	}
	for _, unexpected := range [][]byte{[]byte(`api('/ai/settings`), []byte(`remoteBackup()`)} {
		if bytes.Contains(settings, unexpected) {
			t.Fatalf("settings page still contains separated feature settings %q", unexpected)
		}
	}

	aiPage, err := os.ReadFile("../../web/templates/ai_diagnostics.html")
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range [][]byte{[]byte(`@click="openAISettings()"`), []byte(`api('/ai/settings`), []byte(`api('/ai/test`)} {
		if !bytes.Contains(aiPage, expected) {
			t.Fatalf("AI diagnostics settings modal is missing %q", expected)
		}
	}

	backups, err := os.ReadFile("../../web/templates/backups.html")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(backups, []byte(`/backups/remote-settings`)) {
		t.Fatal("backup overview is missing the remote settings entry")
	}
}

func TestSettingsSystemUpdatesStayCompact(t *testing.T) {
	settings, err := os.ReadFile("../../web/templates/settings.html")
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range [][]byte{
		[]byte(`@click="setSection('updates')"`),
		[]byte(`x-show="activeSection === 'updates'"`),
		[]byte(`id="system-updates" x-data="systemUpdate()"`),
		[]byte(`listOpen: false`),
		[]byte(`x-show="listOpen"`),
		[]byte(`style="max-height: 22rem; overflow-y: auto; overscroll-behavior: contain;"`),
		[]byte(`x-for="pkg in filteredPackages"`),
		[]byte(`filter === 'security'`),
		[]byte(`filter === 'regular'`),
		[]byte(`@click="listOpen = !listOpen"`),
		[]byte(`@click="check(true)"`),
		[]byte(`@click="doUpdate()"`),
		[]byte(`api('/system/updates' + (fresh ? '?fresh=1' : ''))`),
		[]byte(`api('/system/updates/status')`),
		[]byte(`api('/system/updates/do', { method: 'POST' })`),
		[]byte(`this.resume(true)`),
		[]byte(`x-show="lastMessage && !msg"`),
		[]byte(`setTimeout(() => this.dismissStatus(), 10000)`),
		[]byte(`@click="dismissStatus()"`),
	} {
		if !bytes.Contains(settings, expected) {
			t.Fatalf("compact system update panel is missing %q", expected)
		}
	}
	component := regexp.MustCompile(`<[^>]+\bid="system-updates"[^>]*>`).Find(settings)
	if bytes.Contains(component, []byte(`x-init=`)) {
		t.Fatal("system update component must use Alpine auto init without a second explicit initialization")
	}
	if bytes.Contains(settings, []byte(`space-y-2 max-h-80 overflow-y-auto`)) {
		t.Fatal("system update list still depends on an uncompiled max-h-80 utility")
	}
}

func TestDashboardUpdateBadgesDeepLinkToSystemUpdates(t *testing.T) {
	source, err := os.ReadFile("../../web/templates/dashboard.html")
	if err != nil {
		t.Fatal(err)
	}
	deepLink := []byte(`href="/{{.RandomSuffix}}/settings#system-updates"`)
	if count := bytes.Count(source, deepLink); count != 2 {
		t.Fatalf("dashboard update badges deep-link count = %d, want 2", count)
	}
}

func TestSettingsSystemUpdateCompletionDoesNotPersistAsBanner(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is not available")
	}
	rendered := renderPage(t, "settings.html", "settings_content")
	scripts := regexp.MustCompile(`(?s)<script>(.*?)</script>`).FindAllSubmatch(rendered, -1)
	var pageScript []byte
	for _, script := range scripts {
		if bytes.Contains(script[1], []byte("function systemUpdate()")) {
			pageScript = script[1]
			break
		}
	}
	if len(pageScript) == 0 {
		t.Fatal("settings system update script not found")
	}
	harness := []byte(`
let scheduled = null;
globalThis.setTimeout = (fn, ms) => { scheduled = { fn, ms }; return 1; };
globalThis.clearTimeout = () => {};

const restored = systemUpdate();
restored.check = () => {};
restored.applyStatus({ status: 'success', message: 'done', stage: 'complete', updated_at: '2026-09-30T03:00:00Z' }, true);
if (restored.msg !== '' || restored.lastMessage !== 'done' || restored.lastUpdatedAt === '') {
    throw new Error('restored success should be compact history, not a banner');
}

const active = systemUpdate();
active.check = () => {};
active.updating = true;
active.applyStatus({ status: 'success', message: 'done', stage: 'complete', updated_at: '2026-09-30T03:00:00Z' }, false);
if (active.msg !== 'done' || !scheduled || scheduled.ms !== 10000) {
    throw new Error('fresh success should display temporarily');
}
scheduled.fn();
if (active.msg !== '' || active.lastMessage !== 'done') {
    throw new Error('success banner should collapse into compact history');
}

const failed = systemUpdate();
failed.check = () => {};
scheduled = null;
failed.applyStatus({ status: 'failed', message: 'failed', detail: 'detail', stage: 'packages', updated_at: '2026-09-30T03:00:00Z' }, true);
if (failed.msg !== 'failed' || !failed.failed || scheduled !== null) {
    throw new Error('failure should remain visible until dismissed');
}
`)
	testScript := append(append([]byte{}, pageScript...), harness...)
	scriptPath := filepath.Join(t.TempDir(), "settings-system-update-status.js")
	if err := os.WriteFile(scriptPath, testScript, 0600); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command(node, scriptPath).CombinedOutput(); err != nil {
		t.Fatalf("settings system update status behavior failed: %v\n%s", err, output)
	}
}

func TestContentTemplatesRender(t *testing.T) {
	contents := []string{
		"dashboard_content", "websites_content", "wordpress_overview_content", "websites_new_content",
		"websites_detail_content", "wordpress_site_detail_content", "databases_content", "database_detail_content", "ai_diagnostics_content", "log_analysis_content", "cron_content", "backups_content", "remote_backup_settings_content", "firewall_content",
		"files_content", "security_content", "settings_content",
		"alert_content", "software_content", "vps_content", "help_content",
	}
	for _, content := range contents {
		t.Run(content, func(t *testing.T) {
			tmpl := parseTemplates(t)
			var output bytes.Buffer
			if err := tmpl.ExecuteTemplate(&output, content, testPageData("")); err != nil {
				t.Fatalf("render %s: %v", content, err)
			}
		})
	}
}

func TestRenderedPageScriptsParse(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is not available")
	}

	scriptPattern := regexp.MustCompile(`(?s)<script>(.*?)</script>`)
	for page, content := range pageTemplates {
		t.Run(page, func(t *testing.T) {
			rendered := renderPage(t, page, content)
			for index, script := range scriptPattern.FindAllSubmatch(rendered, -1) {
				if len(bytes.TrimSpace(script[1])) == 0 {
					continue
				}
				scriptPath := filepath.Join(t.TempDir(), fmt.Sprintf("%s-%d.js", page, index))
				if err := os.WriteFile(scriptPath, script[1], 0600); err != nil {
					t.Fatal(err)
				}
				if output, err := exec.Command(node, "--check", scriptPath).CombinedOutput(); err != nil {
					t.Fatalf("%s inline script %d: invalid JavaScript: %v\n%s", page, index+1, err, output)
				}
			}
		})
	}
}

func TestAIDevelopmentForceRetryStartsAfterOuterBusyCleanup(t *testing.T) {
	page := string(renderPage(t, "website_detail.html", "websites_detail_content"))
	start := strings.Index(page, "async enableAIDevelopment(force)")
	end := strings.Index(page[start:], "async downloadAIDevelopmentCredential()")
	if start < 0 || end < 0 {
		t.Fatal("AI development enable function missing")
	}
	body := page[start : start+end]
	cleanup := strings.Index(body, "} finally {")
	retry := strings.Index(body, "if (retryForce) return this.enableAIDevelopment(true)")
	if cleanup < 0 || retry < cleanup {
		t.Fatal("forced retry can be cleared by the outer finally")
	}
}

func TestWebsiteMaintenanceUsesSinglePasswordField(t *testing.T) {
	page := renderPage(t, "website_detail.html", "websites_detail_content")
	if got := bytes.Count(page, []byte(`x-model="maintenancePasswordInput"`)); got != 1 {
		t.Fatalf("maintenance password field count = %d, want 1", got)
	}
	for _, obsolete := range [][]byte{
		[]byte("maintenanceSavedPassword"),
		[]byte(`x-ref="maintenancePassword"`),
	} {
		if bytes.Contains(page, obsolete) {
			t.Fatalf("rendered page still contains obsolete maintenance password state %q", obsolete)
		}
	}
	if !bytes.Contains(page, []byte(`password: this.maintenancePasswordInput`)) {
		t.Fatal("maintenance settings do not submit the unified password field")
	}
}

func TestWebsiteLogRoutesRegistered(t *testing.T) {
	source, err := os.ReadFile("router.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, route := range []string{
		`protected.GET("/api/websites/:id/log-files", websiteHandler.ListLogFiles)`,
		`protected.GET("/api/websites/:id/logs/download", websiteHandler.DownloadLogFile)`,
	} {
		if !bytes.Contains(source, []byte(route)) {
			t.Fatalf("router.go missing route %s", route)
		}
	}
}

func TestWebsiteProtectionRoutesRegistered(t *testing.T) {
	source, err := os.ReadFile("router.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, route := range []string{
		`protected.PUT("/api/websites/:id/file-editor", websiteHandler.SetFileEditingProtection)`,
		`protected.PUT("/api/websites/:id/file-lock", websiteHandler.SetFileLock)`,
		`protected.GET("/api/websites/:id/file-lock/preview", websiteHandler.PreviewFileLock)`,
	} {
		if !bytes.Contains(source, []byte(route)) {
			t.Fatalf("router.go missing route %s", route)
		}
	}
}

func TestWPInventoryRoutesRegistered(t *testing.T) {
	source, err := os.ReadFile("router.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, route := range []string{
		`protected.GET("/api/websites/:id/wp-inventory", wpInventoryHandler.Summary)`,
		`protected.POST("/api/websites/:id/wp-inventory/refresh", wpInventoryHandler.Refresh)`,
		`protected.GET("/api/websites/:id/wp-inventory/tasks/:task_id", wpInventoryHandler.Task)`,
		`protected.GET("/api/websites/:id/wp-inventory/components", wpInventoryHandler.Components)`,
		`protected.GET("/api/websites/:id/wp-inventory/updates", wpInventoryHandler.Updates)`,
	} {
		if !bytes.Contains(source, []byte(route)) {
			t.Fatalf("router.go missing protected inventory route %s", route)
		}
	}
}

func TestWPCoreUpdateRoutesRegisteredOnProtectedGroup(t *testing.T) {
	source, err := os.ReadFile("router.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, route := range []string{
		`protected.GET("/api/websites/:id/wp-core-update/preview", wpCoreUpdateHandler.Preview)`,
		`protected.POST("/api/websites/:id/wp-core-update/confirm", wpCoreUpdateHandler.Confirm)`,
		`protected.GET("/api/websites/:id/wp-core-update/tasks/latest", wpCoreUpdateHandler.LatestTask)`,
		`protected.GET("/api/websites/:id/wp-core-update/tasks/:task_id", wpCoreUpdateHandler.Task)`,
	} {
		if !bytes.Contains(source, []byte(route)) {
			t.Fatalf("missing protected route %s", route)
		}
	}
}

func TestWPCoreUpdateHandlerKeepsNilInterfaceWhenConstructionFails(t *testing.T) {
	handler := newWPCoreUpdateHandler(nil, "")
	if handler == nil || handler.Service != nil {
		t.Fatalf("failed construction left a typed nil service: %#v", handler)
	}
}

func TestWPPluginUpdateRoutesRegisteredOnProtectedGroup(t *testing.T) {
	source, err := os.ReadFile("router.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, route := range []string{
		`protected.GET("/api/websites/:id/wp-plugin-update/preview", wpPluginUpdateHandler.Preview)`,
		`protected.POST("/api/websites/:id/wp-plugin-update/confirm", wpPluginUpdateHandler.Confirm)`,
		`protected.GET("/api/websites/:id/wp-plugin-update/tasks/latest", wpPluginUpdateHandler.LatestTask)`,
		`protected.GET("/api/websites/:id/wp-plugin-update/tasks/:task_id", wpPluginUpdateHandler.Task)`,
	} {
		if !bytes.Contains(source, []byte(route)) {
			t.Fatalf("missing protected route %s", route)
		}
	}
}

func TestWPPluginUpdateHandlerKeepsNilInterfaceWhenConstructionFails(t *testing.T) {
	handler := newWPPluginUpdateHandler(nil, "")
	if handler == nil || handler.Service != nil {
		t.Fatalf("failed construction left a typed nil service: %#v", handler)
	}
}

func TestWPThemeUpdateRoutesRegisteredOnProtectedGroup(t *testing.T) {
	source, err := os.ReadFile("router.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, route := range []string{
		`protected.GET("/api/websites/:id/wp-theme-update/preview", wpThemeUpdateHandler.Preview)`,
		`protected.POST("/api/websites/:id/wp-theme-update/confirm", wpThemeUpdateHandler.Confirm)`,
		`protected.GET("/api/websites/:id/wp-theme-update/tasks/latest", wpThemeUpdateHandler.LatestTask)`,
		`protected.GET("/api/websites/:id/wp-theme-update/tasks/:task_id", wpThemeUpdateHandler.Task)`,
	} {
		if !bytes.Contains(source, []byte(route)) {
			t.Fatalf("missing protected route %s", route)
		}
	}
}

func TestWPThemeUpdateHandlerKeepsNilInterfaceWhenConstructionFails(t *testing.T) {
	handler := newWPThemeUpdateHandler(nil, "")
	if handler == nil || handler.Service != nil {
		t.Fatalf("failed construction left a typed nil service: %#v", handler)
	}
}

func TestWPFleetOverviewRouteRegistered(t *testing.T) {
	source, err := os.ReadFile("router.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, route := range [][]byte{
		[]byte(`protected.GET("/api/wp-fleet/overview", wpFleetOverviewHandler.Overview)`),
		[]byte(`protected.POST("/api/wp-fleet/inventory-refresh", wpFleetOverviewHandler.RefreshAll)`),
		[]byte(`protected.PUT("/api/websites/:id/wp-update-checks", websiteHandler.SetWPUpdateChecks)`),
	} {
		if !bytes.Contains(source, route) {
			t.Fatalf("router.go missing protected fleet route %s", route)
		}
	}
}

func TestLoginRouteUsesCSRFMiddleware(t *testing.T) {
	source, err := os.ReadFile("router.go")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(source, []byte(`panelGroup.POST("/api/auth/login", middleware.CSRF(), func(c *gin.Context)`)) {
		t.Fatal("login route is missing CSRF middleware")
	}
	for _, required := range [][]byte{
		[]byte(`panelGroup.GET("/api/auth/csrf-token", func(c *gin.Context)`),
		[]byte(`c.Header("Cache-Control", "no-store, no-cache, must-revalidate")`),
		[]byte(`if !middleware.SetCSRFToken(c)`),
	} {
		if !bytes.Contains(source, required) {
			t.Fatalf("login CSRF recovery is missing %q", required)
		}
	}
	login, err := os.ReadFile("../../web/templates/login.html")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range [][]byte{
		[]byte(`async refreshCSRFToken()`),
		[]byte(`cache: 'no-store'`),
		[]byte(`credentials: 'same-origin'`),
		[]byte(`if (e.status !== 403 || attempt > 0) throw e;`),
	} {
		if !bytes.Contains(login, required) {
			t.Fatalf("login template CSRF recovery is missing %q", required)
		}
	}
}

func TestWPFleetOverviewPanelIsIsolatedAndWired(t *testing.T) {
	websites, err := os.ReadFile("../../web/templates/websites.html")
	if err != nil {
		t.Fatal(err)
	}
	panel, err := os.ReadFile("../../web/templates/wp_fleet_overview.html")
	if err != nil {
		t.Fatal(err)
	}
	overviewPage, err := os.ReadFile("../../web/templates/wordpress_overview.html")
	if err != nil {
		t.Fatal(err)
	}
	call := []byte(`{{template "wp_fleet_overview" .}}`)
	if count := bytes.Count(websites, call); count != 0 {
		t.Fatalf("websites fleet overview template calls = %d, want 0", count)
	}
	if count := bytes.Count(overviewPage, call); count != 1 {
		t.Fatalf("WordPress overview fleet template calls = %d, want 1", count)
	}
	for _, required := range [][]byte{
		[]byte(`api('/websites')`),
		[]byte(`websites: []`),
		[]byte(`fetchList()`),
	} {
		if !bytes.Contains(websites, required) {
			t.Fatalf("websites template is missing restored list behavior %q", required)
		}
	}
	for _, forbidden := range [][]byte{
		[]byte(`function wpFleetOverview()`),
		[]byte(`/wp-fleet/overview`),
		[]byte(`healthFilter`),
		[]byte(`inventoryFilter`),
	} {
		if bytes.Contains(websites, forbidden) {
			t.Fatalf("websites template contains fleet implementation %q", forbidden)
		}
	}
	for _, required := range [][]byte{
		[]byte(`{{define "wp_fleet_overview"}}`),
		[]byte(`function wpFleetOverview()`),
		[]byte(`x-data="wpFleetOverview()"`),
		[]byte(`wordpressOnlyOverview(response.data)`),
		[]byte(`site.site_type === 'wordpress'`),
		[]byte(`overview.sites.length > 10`),
	} {
		if !bytes.Contains(panel, required) {
			t.Fatalf("fleet overview panel is missing %q", required)
		}
	}
	for _, forbidden := range [][]byte{
		[]byte(`reloadOverview`),
		[]byte(`wp_fleet.reload`),
		[]byte(`function toggleStatus(`),
		[]byte(`function reinstallWP(`),
		[]byte(`function deleteSite(`),
		[]byte(`{{template "base" .}}`),
		[]byte(`siteTypeFilter`),
		[]byte(`filter_php`),
		[]byte(`@click="toggleStatus(site)"`),
		[]byte(`@click="reinstallWP(site)"`),
		[]byte(`@click="deleteSite(site)"`),
	} {
		if bytes.Contains(panel, forbidden) {
			t.Fatalf("fleet overview panel contains duplicated write behavior %q", forbidden)
		}
	}
	rendered := renderPage(t, "wordpress_overview.html", "wordpress_overview_content")
	if !bytes.Contains(rendered, []byte(`function wpFleetOverview()`)) {
		t.Fatal("rendered WordPress overview page is missing the fleet overview component")
	}
}

func TestWebsiteListShowsDistinctMonitoringStatesInCompactColumns(t *testing.T) {
	websites, err := os.ReadFile("../../web/templates/websites.html")
	if err != nil {
		t.Fatal(err)
	}
	header := regexp.MustCompile(`(?s)<thead>(.*?)</thead>`).FindSubmatch(websites)
	if len(header) != 2 || bytes.Count(header[1], []byte(`scope="col"`)) != 5 {
		t.Fatal("website registry must keep five labeled columns")
	}
	row := regexp.MustCompile(`(?s)<template x-for="site in filteredWebsites"[^>]*>(.*?)</template>`).FindSubmatch(websites)
	if len(row) != 2 {
		t.Fatal("website list is missing its site row")
	}
	cells := regexp.MustCompile(`(?s)<td\b[^>]*>(.*?)</td>`).FindAllSubmatch(row[1], -1)
	if len(cells) != 5 {
		t.Fatalf("website row cell count = %d, want 5", len(cells))
	}
	for _, required := range [][]byte{
		[]byte(`{{t .Lang "website.online_monitoring"}}`),
		[]byte(`{{t .Lang "website.anomaly_monitoring"}}`),
		[]byte(`site.monitoring_enabled`),
		[]byte(`site.anomaly_monitoring_applicable`),
		[]byte(`site.anomaly_monitoring_enabled`),
		[]byte(`t('website.not_applicable')`),
	} {
		if !bytes.Contains(cells[2][1], required) {
			t.Fatalf("compact monitoring cell missing distinct state %q", required)
		}
	}
	for _, required := range [][]byte{
		[]byte(`{{t .Lang "website.registry_monitoring"}}`),
		[]byte(`site.backup_enabled`),
		[]byte(`colspan="5"`),
		[]byte(`x-model="query"`),
		[]byte(`x-model="statusFilter"`),
		[]byte(`x-show="loading && !loaded"`),
		[]byte(`x-show="loaded && !loading && !loadError && websites.length === 0"`),
		[]byte(`@click="openMore($event, site)"`),
		[]byte(`x-teleport="body"`),
	} {
		if !bytes.Contains(websites, required) {
			t.Fatalf("compact website list missing %q", required)
		}
	}
	for _, required := range [][]byte{
		[]byte(`/websites/' + site.id`),
		[]byte(`/files?site_id=' + site.id`),
	} {
		// Details and files remain directly reachable beside the more menu.
		if !bytes.Contains(cells[4][1], required) {
			t.Fatalf("primary website action missing %q", required)
		}
	}
	if bytes.Contains(websites, []byte(`site.litespeed_cache_enabled`)) {
		t.Fatal("website registry must not label the legacy default cache policy as actual cache status")
	}
}

func TestWebsiteListShowsStatusTaskMessage(t *testing.T) {
	websites, err := os.ReadFile("../../web/templates/websites.html")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(websites, []byte(`showToast(resp.data?.message || t('common.operation_success'), 'success')`)) {
		t.Fatal("website status action does not display the task result message")
	}
	if !bytes.Contains(websites, []byte(`if (status === 'deleting') return t('website.status_deleting')`)) {
		t.Fatal("website list does not display the persisted deleting state")
	}
}

func TestWebsiteListHoverStyleIsCompiled(t *testing.T) {
	css, err := os.ReadFile("../../web/css/main.css")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(css, []byte(`hover\:bg-gray-700\/40:hover`)) {
		t.Fatal("compiled CSS is missing the website row hover rule")
	}
}

func TestWPFleetOverviewPanelAPIContract(t *testing.T) {
	panel, err := os.ReadFile("../../web/templates/wp_fleet_overview.html")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range [][]byte{
		[]byte(`api('/wp-fleet/overview', { signal: controller.signal, suppressToast: true })`),
		[]byte(`api('/wp-fleet/inventory-refresh', { method: 'POST' })`),
		[]byte(`api('/websites/' + site.id + '/wp-inventory/refresh', { method: 'POST', suppressToast: true })`),
		[]byte(`api('/websites/' + site.id + '/wp-update-checks'`),
		[]byte(`inventory?.failure_code`),
		[]byte(`new TextEncoder().encode(query).length > 128`),
		[]byte(`toLocaleDateString(currentLocale())`),
		[]byte(`toLocaleString(currentLocale())`),
	} {
		if !bytes.Contains(panel, required) {
			t.Fatalf("fleet overview panel is missing API contract %q", required)
		}
	}
	for _, forbidden := range [][]byte{
		[]byte(`setInterval(`),
		[]byte(`toLocaleDateString('zh-CN')`),
		[]byte(`toLocaleString('zh-CN')`),
	} {
		if bytes.Contains(panel, forbidden) {
			t.Fatalf("fleet overview panel contains forbidden API behavior %q", forbidden)
		}
	}
}

func TestWPFleetOverviewPanelBehavior(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is not available")
	}
	script := wpFleetOverviewPanelScript(t)
	harness := []byte(`
function assert(condition, message) {
    if (!condition) throw new Error(message);
}
global.t = (key, params = {}) => key + (params.count === undefined ? '' : ':' + params.count);
global.currentLocale = () => 'en-US';
global.showToast = () => {};

const inventory = (status, successful, updates, stale = false) => ({
    status,
    has_successful_inventory: successful,
    wordpress_version: successful ? '7.0' : '',
    plugin_updates: updates,
    theme_updates: 0,
    core_upgrade_available: false,
    update_total: updates,
    last_attempt_at: '2026-07-21T00:00:00Z',
    last_success_at: successful ? '2026-07-21T00:00:00Z' : null,
    stale,
});
const site = (id, domain, siteType, status, health, siteInventory, createdAt) => ({
    id,
    name: domain.split('.')[0],
    domain,
    site_type: siteType,
    status,
    created_at: createdAt || '2026-07-21T00:00:00Z',
    expires_at: null,
    ssl_enabled: false,
    ssl_state: 'disabled',
    monitoring_enabled: false,
    backup_enabled: false,
    file_lock_enabled: false,
    litespeed_cache_enabled: false,
    access_log_mode: 'off',
    update_checks_disabled: false,
    health: { level: health, issues: [] },
    inventory: siteInventory,
});
const sites = [
    site(1, 'alpha.example', 'wordpress', 'active', 'critical', inventory('complete', true, 1), '2026-07-20T00:00:00Z'),
    site(2, 'beta.example', 'wordpress', 'paused', 'warning', inventory('failed', true, 2, true), '2026-07-19T00:00:00Z'),
    site(3, 'gamma.example', 'wordpress', 'creating', 'unknown', inventory('unknown', false, 0), '2026-07-18T00:00:00Z'),
    site(4, 'delta.example', 'php', 'active', 'healthy', null, '2026-07-17T00:00:00Z'),
    site(5, 'epsilon.example', 'wordpress', 'deleting', 'healthy', inventory('complete', true, 0), '2026-07-21T00:00:00Z'),
];
const counts = {
    total_sites: 5,
    wordpress_sites: 4,
    critical_sites: 1,
    warning_sites: 1,
    unknown_sites: 1,
    healthy_sites: 2,
    update_sites: 2,
    failed_inventory_sites: 1,
    stale_inventory_sites: 1,
    inventory_attention_sites: 1,
    uncollected_sites: 1,
};
const data = (nextSites = sites, nextCounts = counts) => ({ generated_at: '2026-07-21T00:00:00Z', counts: nextCounts, sites: nextSites });

(async () => {
    const panel = wpFleetOverview();
    panel.overview = panel.wordpressOnlyOverview(data());

    assert(panel.tileTone(0, 'orange').box === 'border-gray-700 bg-gray-800/70', 'zero count should render neutral tile');
    assert(panel.tileTone(0, 'orange').label === 'text-gray-400', 'zero count should render neutral label');
    assert(panel.tileTone(1, 'orange').box === 'border-orange-900/70 bg-orange-950/20', 'nonzero orange count should render orange tile');
    assert(panel.tileTone(2, 'red').value === 'text-red-200', 'nonzero red count should render red value');
    assert(panel.tileTone(3, 'yellow').label === 'text-yellow-300', 'nonzero yellow count should render yellow label');

    assert(panel.filteredSites().map(item => item.id).join(',') === '1,2,3,5', 'PHP sites automatically excluded');
    assert(panel.overview.counts.total_sites === 4 && panel.overview.counts.healthy_sites === 1, 'WordPress-only counts');
    panel.healthFilter = 'warning';
    panel.updateFilter = 'has_updates';
    panel.search = ' beta ';
    assert(panel.filteredSites().map(item => item.id).join(',') === '2', 'combined filtering');

    panel.healthFilter = 'all';
    panel.updateFilter = 'all';
    panel.search = 'a'.repeat(128);
    panel.filteredSites();
    assert(panel.searchError === '', '128 byte search accepted');
    panel.search = '测'.repeat(43);
    assert(panel.filteredSites().length === 0 && panel.searchError === 'wp_fleet.search_too_long', '129 byte search rejected');

    panel.search = '';
    assert(panel.filteredSites().map(item => item.id).join(',') === '1,2,3,5', 'attention sorting remains fixed');

    assert(['active', 'paused', 'error', 'creating', 'deleting'].map(value => panel.statusKey(value)).join(',') === [
        'wp_fleet.status_active', 'wp_fleet.status_paused', 'wp_fleet.status_error', 'wp_fleet.status_creating', 'wp_fleet.status_deleting'
    ].join(','), 'five website statuses');
	assert(panel.inventoryErrorKey({ failure_code: 'php_cli_unavailable' }) === 'wp_inventory.error_php_runtime', 'fleet exposes actionable LSPHP error');
	assert(panel.inventoryErrorKey({ failure_code: 'insufficient_privileges' }) === 'wp_inventory.error_permissions', 'fleet exposes actionable permissions error');
	assert(panel.inventoryErrorKey({ failure_code: 'future_error' }) === 'wp_inventory.error_unknown', 'fleet error fallback');

    let usedLocale = '';
    const originalDate = Date.prototype.toLocaleDateString;
    Date.prototype.toLocaleDateString = function(locale) { usedLocale = locale; return 'date'; };
    assert(panel.displayDate('2026-07-21T00:00:00Z') === 'date' && usedLocale === 'en-US', 'current locale date');
    Date.prototype.toLocaleDateString = originalDate;

    let resolveFirst;
    let resolveSecond;
    let calls = 0;
    global.api = () => new Promise(resolve => {
        calls++;
        if (calls === 1) resolveFirst = resolve;
        else resolveSecond = resolve;
    });
    const first = panel.loadOverview();
    const second = panel.loadOverview();
    const secondData = data([sites[4]], { ...counts, total_sites: 1, critical_sites: 0, warning_sites: 0, unknown_sites: 0, healthy_sites: 1 });
    resolveSecond({ data: secondData });
    await second;
    resolveFirst({ data: data([sites[0]]) });
    await first;
    assert(panel.overview.sites[0].id === 5, 'old response discarded');
    assert(panel.overview.counts.total_sites === 1, 'counts use API response');

    const previous = panel.overview;
    global.api = async () => { throw new Error('reload failed'); };
    await panel.loadOverview();
    assert(panel.overview === previous && panel.staleOverview && panel.loadError === 'reload failed', 'reload failure preserves old overview');

    const initialFailure = wpFleetOverview();
    global.api = async () => { throw new Error('initial failed'); };
    await initialFailure.loadOverview();
    assert(initialFailure.overview === null && !initialFailure.staleOverview && initialFailure.loadError === 'initial failed', 'initial failure state');

    const empty = wpFleetOverview();
    global.api = async () => ({ data: data([], { ...counts, total_sites: 0, critical_sites: 0, warning_sites: 0, unknown_sites: 0, healthy_sites: 0 }) });
    await empty.loadOverview();
    assert(Array.isArray(empty.overview.sites) && empty.overview.sites.length === 0, 'empty state');

    const bulk = wpFleetOverview();
    bulk.overview = bulk.wordpressOnlyOverview(data());
    global.api = async (path, options = {}) => {
        if (path === '/wp-fleet/inventory-refresh') {
            assert(options.method === 'POST', 'bulk refresh uses POST');
            return { data: { site_ids: [1, 2], created: 1, existing: 1, failed: 0 } };
        }
        if (path === '/wp-fleet/overview') {
            return { data: data([sites[0], sites[1]], { ...counts, total_sites: 2 }) };
        }
        throw new Error('unexpected API path ' + path);
    };
    await bulk.startBulkRefresh();
    assert(!bulk.bulkRefresh.running && bulk.bulkRefresh.finished, 'bulk refresh reaches terminal state');
    assert(bulk.bulkRefresh.total === 2 && bulk.bulkRefresh.succeeded === 1 && bulk.bulkRefresh.failed === 1 && bulk.bulkRefresh.existing === 1, 'bulk refresh progress summary');

    const restricted = site(6, 'restricted.example', 'wordpress', 'active', 'healthy', inventory('complete', true, 3));
    restricted.update_checks_disabled = true;
    panel.overview = panel.wordpressOnlyOverview(data([sites[0], restricted], { ...counts, total_sites: 2 }));
    panel.updateFilter = 'has_updates';
    assert(panel.filteredSites().map(item => item.id).join(',') === '1', 'disabled sites excluded from has-updates filter');
    panel.updateFilter = 'no_updates';
    assert(panel.filteredSites().length === 0, 'disabled sites excluded from no-updates filter');
    assert(panel.overview.counts.update_sites === 1 && panel.disabledUpdateCheckCount() === 1, 'disabled sites excluded from update count');

    global.api = async (path, options = {}) => {
        if (path === '/websites/6/wp-update-checks') {
            assert(options.method === 'PUT' && options.body.enabled === true, 'quick toggle request');
            return { data: { enabled: true } };
        }
        if (path === '/wp-fleet/overview') {
            const refreshed = { ...restricted, update_checks_disabled: false, health: { level: 'warning', issues: ['updates_available'] } };
            return { data: data([refreshed], { ...counts, total_sites: 1 }) };
        }
        throw new Error('unexpected toggle path ' + path);
    };
    await panel.toggleUpdateChecks(restricted);
    assert(panel.overview.sites[0].update_checks_disabled === false && panel.overview.sites[0].health.level === 'warning' && panel.updateCheckSavingSiteID === null, 'quick toggle reloads authoritative row health and clears saving state');

    const failedToggle = panel.overview.sites[0];
    global.api = async () => { throw new Error('toggle failed'); };
    await panel.toggleUpdateChecks(failedToggle);
    assert(failedToggle.update_checks_disabled === false && panel.updateCheckSavingSiteID === null, 'failed toggle preserves row state');

    restricted.update_checks_disabled = true;
    const restrictedBulk = wpFleetOverview();
    restrictedBulk.overview = restrictedBulk.wordpressOnlyOverview(data([restricted], { ...counts, total_sites: 1 }));
    global.api = async (path) => {
        if (path === '/wp-fleet/inventory-refresh') return { data: { site_ids: [6], created: 1, existing: 0, failed: 0 } };
        if (path === '/wp-fleet/overview') return { data: data([restricted], { ...counts, total_sites: 1 }) };
        throw new Error('unexpected restricted API path ' + path);
    };
    await restrictedBulk.startBulkRefresh();
    assert(restrictedBulk.bulkRefresh.restricted === 1 && restrictedBulk.bulkRefresh.succeeded === 0 && restrictedBulk.bulkRefresh.failed === 0, 'restricted completion bucket');

    const retrying = wpFleetOverview();
    retrying.overview = retrying.wordpressOnlyOverview(data([sites[4]], { ...counts, total_sites: 1 }));
    retrying.bulkRefresh = { running: true, finished: false, total: 1, completed: 0, succeeded: 0, restricted: 0, failed: 0, enqueueFailed: 0, existing: 0, siteIDs: [5], error: '' };
    let loadAttempts = 0;
    retrying.loadOverview = async () => {
        loadAttempts++;
        if (loadAttempts === 1) return null;
        if (loadAttempts < 4) return false;
        return true;
    };
    const originalTimeout = global.setTimeout;
    global.setTimeout = callback => { callback(); return 0; };
    await retrying.pollBulkRefresh();
    global.setTimeout = originalTimeout;
    assert(loadAttempts === 5 && retrying.bulkRefresh.finished && !retrying.bulkRefresh.error, 'superseded and transient failures are retried before final reload');

    const many = [];
    for (let index = 0; index < 300; index++) many.push(site(index + 10, 'site-' + index + '.example', 'wordpress', 'active', index % 2 ? 'healthy' : 'warning', inventory('complete', true, index % 3), '2026-07-21T00:00:00Z'));
    panel.overview = data(many, counts);
    panel.updateFilter = 'all';
    panel.search = 'site';
    assert(panel.filteredSites().length === 300, '300 site filtering warmup');
    const started = performance.now();
    for (let iteration = 0; iteration < 5; iteration++) {
        assert(panel.filteredSites().length === 300, '300 site filtering');
    }
    const filterElapsed = (performance.now() - started) / 5;
    assert(filterElapsed < 50, '300 site filtering budget');
    console.log('fleet-filter-300-ms=' + filterElapsed.toFixed(3));
})().catch(error => {
    console.error(error);
    process.exit(1);
});
`)
	testScript := append(append([]byte{}, script...), harness...)
	scriptPath := filepath.Join(t.TempDir(), "wp-fleet-overview-behavior.js")
	if err := os.WriteFile(scriptPath, testScript, 0600); err != nil {
		t.Fatal(err)
	}
	output, err := exec.Command(node, scriptPath).CombinedOutput()
	if err != nil {
		t.Fatalf("fleet overview behavior failed: %v\n%s", err, output)
	}
	if output = bytes.TrimSpace(output); len(output) > 0 {
		t.Log(string(output))
	}
}

func wpFleetOverviewPanelScript(t *testing.T) []byte {
	t.Helper()
	rendered := renderPage(t, "wordpress_overview.html", "wordpress_overview_content")
	scriptPattern := regexp.MustCompile(`(?s)<script>(.*?)</script>`)
	for _, match := range scriptPattern.FindAllSubmatch(rendered, -1) {
		if bytes.Contains(match[1], []byte(`function wpFleetOverview()`)) {
			return match[1]
		}
	}
	t.Fatal("rendered WordPress overview page is missing the fleet overview script")
	return nil
}

func TestWPInventoryPanelIsIsolatedAndWired(t *testing.T) {
	detail, err := os.ReadFile("../../web/templates/website_detail.html")
	if err != nil {
		t.Fatal(err)
	}
	panel, err := os.ReadFile("../../web/templates/wp_inventory_panel.html")
	if err != nil {
		t.Fatal(err)
	}
	wordpressDetail, err := os.ReadFile("../../web/templates/wordpress_site_detail.html")
	if err != nil {
		t.Fatal(err)
	}
	call := []byte(`{{template "wp_inventory_panel" .}}`)
	if count := bytes.Count(detail, call); count != 0 {
		t.Fatalf("website management inventory template calls = %d, want 0", count)
	}
	if count := bytes.Count(wordpressDetail, call); count != 1 {
		t.Fatalf("WordPress detail inventory template calls = %d, want 1", count)
	}
	for _, forbidden := range [][]byte{
		[]byte(`function wpInventoryPanel()`),
		[]byte(`/wp-inventory`),
		[]byte(`pollTimer`),
	} {
		if bytes.Contains(detail, forbidden) {
			t.Fatalf("website detail contains inventory implementation %q", forbidden)
		}
	}
	for _, required := range [][]byte{
		[]byte(`{{define "wp_inventory_panel"}}`),
		[]byte(`function wpInventoryPanel()`),
		[]byte(`x-effect="setSite(site)"`),
		[]byte(`x-show="site && site.site_type === 'wordpress'"`),
	} {
		if !bytes.Contains(panel, required) {
			t.Fatalf("inventory panel is missing %q", required)
		}
	}
	if bytes.Contains(panel, []byte(`{{template "base" .}}`)) {
		t.Fatal("inventory panel must not render the base template")
	}
	rendered := renderPage(t, "wordpress_site_detail.html", "wordpress_site_detail_content")
	if !bytes.Contains(rendered, []byte(`function wpInventoryPanel()`)) {
		t.Fatal("rendered WordPress detail is missing the inventory component")
	}
	if !bytes.Contains(rendered, []byte(`function wordpressSiteDetail()`)) {
		t.Fatal("rendered WordPress detail is missing its site loader")
	}
}

func TestWPCoreUpdatePanelIsWiredAndUsesFixedAPIContract(t *testing.T) {
	panel, err := os.ReadFile("../../web/templates/wp_core_update_panel.html")
	if err != nil {
		t.Fatal(err)
	}
	detail, err := os.ReadFile("../../web/templates/wordpress_site_detail.html")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range [][]byte{
		[]byte(`{{template "wp_core_update_panel" .}}`),
		[]byte(`api('/websites/' + siteID + '/wp-core-update/preview'`),
		[]byte(`api('/websites/' + siteID + '/wp-core-update/confirm'`),
		[]byte(`api('/websites/' + siteID + '/wp-core-update/tasks/latest'`),
		[]byte(`'/wp-core-update/tasks/' + encodeURIComponent(taskID)`),
		[]byte(`confirmation_token: preview.confirmation_token`),
		[]byte(`target_version: preview.target_version`),
		[]byte(`database_backup_mode: this.databaseBackupMode`),
		[]byte(`signal: this.preparationController.signal`),
		[]byte(`cancelPreparation()`),
		[]byte(`confirm: true`),
		[]byte(`confirmModal(`),
		[]byte(`timeout: 30 * 60 * 1000`),
	} {
		source := panel
		if bytes.HasPrefix(required, []byte(`{{template`)) {
			source = detail
		}
		if !bytes.Contains(source, required) {
			t.Fatalf("core update UI is missing %q", required)
		}
	}
	for _, forbidden := range [][]byte{
		[]byte(`download_url`),
		[]byte(`package_snapshot_path`),
		[]byte(`downloaded_sha256`),
		[]byte(`sessionStorage`),
		[]byte(`setInterval(`),
	} {
		if bytes.Contains(panel, forbidden) {
			t.Fatalf("core update UI contains forbidden behavior %q", forbidden)
		}
	}
	rendered := renderPage(t, "wordpress_site_detail.html", "wordpress_site_detail_content")
	if !bytes.Contains(rendered, []byte(`function wpCoreUpdatePanel()`)) {
		t.Fatal("rendered WordPress detail is missing the core update component")
	}
}

func TestWPCoreUpdatePanelBehavior(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is not available")
	}
	rendered := renderPage(t, "wordpress_site_detail.html", "wordpress_site_detail_content")
	scriptPattern := regexp.MustCompile(`(?s)<script>(.*?)</script>`)
	var script []byte
	for _, match := range scriptPattern.FindAllSubmatch(rendered, -1) {
		if bytes.Contains(match[1], []byte(`function wpCoreUpdatePanel()`)) {
			script = match[1]
			break
		}
	}
	if len(script) == 0 {
		t.Fatal("core update panel script not found")
	}
	harness := []byte(`
function assert(condition, message) { if (!condition) throw new Error(message); }
global.t = (key, params = {}) => key;
global.window = {};
(async () => {
    const panel = wpCoreUpdatePanel();
    panel.siteID = 7;
    assert(panel.validPreview({
        available: true, site_id: 7, current_version: '7.0.1', target_version: '7.0.2',
        confirmation_token: 'opaque', verification_required: 'official_verified',
        database_backup: true, core_files_backup: true, uploads_included: false
    }), 'valid preview rejected');
    assert(!panel.validPreview({ available: true, site_id: 8 }), 'cross-site preview accepted');
    assert(panel.validUpToDate({ available: false, site_id: 7, current_version: '7.0.2' }), 'valid up-to-date response rejected');
    assert(!panel.validUpToDate({ available: false, site_id: 8, current_version: '7.0.2' }), 'cross-site up-to-date response accepted');
    assert(!panel.validUpToDate({ available: true, site_id: 7, current_version: '7.0.2' }), 'available preview accepted as up-to-date');
    assert(!panel.validUpToDate({ available: false, site_id: 7, current_version: '' }), 'empty current_version accepted as up-to-date');

    panel.siteID = 7;
    const originalLoadLatestTask = panel.loadLatestTask;
    const originalLoadPreview = panel.loadPreview;
    let automaticPreviewLoads = 0;
    panel.loadLatestTask = async () => false;
    panel.loadPreview = async () => { automaticPreviewLoads++; };
    await panel.initializeSite(7, panel.generation);
    assert(automaticPreviewLoads === 1, 'page load should automatically prepare the core update preview');
    panel.loadLatestTask = async () => true;
    await panel.initializeSite(7, panel.generation);
    assert(automaticPreviewLoads === 1, 'active task recovery must suppress automatic preview preparation');

    let resolveLatestTask;
    panel.loadLatestTask = () => new Promise(resolve => { resolveLatestTask = resolve; });
    const staleInitialization = panel.initializeSite(7, panel.generation);
    panel.siteID = 8;
    panel.generation++;
    resolveLatestTask(false);
    await staleInitialization;
    assert(automaticPreviewLoads === 1, 'stale site initialization must not prepare a preview');
    panel.siteID = 7;
    panel.loadLatestTask = originalLoadLatestTask.bind(panel);
    panel.loadPreview = originalLoadPreview.bind(panel);

    global.api = async () => ({ data: { available: false, site_id: 7, current_version: '7.0.2' } });
    await panel.loadPreview();
    assert(panel.upToDate && panel.upToDate.current_version === '7.0.2', 'up-to-date response was not recorded');
    assert(panel.preview === null, 'up-to-date response should not populate preview');
    assert(panel.error === '', 'up-to-date response should not surface as an error');

    global.api = async () => ({ data: {
        available: true, site_id: 7, current_version: '7.0.1', target_version: '7.0.2',
        confirmation_token: 'opaque', verification_required: 'official_verified',
        database_backup: true, core_files_backup: true, uploads_included: false
    } });
    await panel.loadPreview();
    assert(panel.upToDate === null, 'up-to-date state was not cleared once an update became available');
    assert(panel.preview && panel.preview.target_version === '7.0.2', 'available preview was not recorded');

    assert(panel.validTask({ task_id: 'wpu_test', site_id: 7, component_type: 'core', task_kind: 'update', status: 'queued' }), 'valid task rejected');
    assert(!panel.validTask({ task_id: 'wpu_test', site_id: 8, component_type: 'core', task_kind: 'update', status: 'queued' }), 'cross-site task accepted');
    panel.task = { status: 'interrupted_unknown', stage: 'health_check' };
    assert(panel.taskStatusText() === 'wp_core_update.status_interrupted_unknown', 'interrupted status mapping');
    assert(panel.stageText() === 'wp_core_update.stage_health_check', 'health-check stage mapping');

    panel.task = null;
    global.api = async () => ({ data: {
        task_id: 'wpu_finished', site_id: 7, component_type: 'core', task_kind: 'update', status: 'failed', stage: 'rollback',
        current_version: '7.0.1', target_version: '7.0.2', requested_at: new Date().toISOString()
    } });
    const bareLoadOfFinishedTask = await panel.loadLatestTask();
    assert(bareLoadOfFinishedTask === false && panel.task === null,
        'a bare page load must not resurrect a finished task as if it just happened');

    global.api = async () => ({ data: {
        task_id: 'wpu_running', site_id: 7, component_type: 'core', task_kind: 'update', status: 'running', stage: 'updating_core',
        current_version: '7.0.1', target_version: '7.0.2', requested_at: new Date().toISOString()
    } });
    const bareLoadOfActiveTask = await panel.loadLatestTask();
    assert(bareLoadOfActiveTask === true && panel.task && panel.task.task_id === 'wpu_running',
        'a bare page load should still resume watching an in-progress task');
    panel.stopPolling();
    panel.task = null;

    panel.task = { task_id: 'stale', site_id: 7, component_type: 'core', task_kind: 'update', status: 'queued', stage: 'queued' };
    let scheduled = 0;
    panel.schedulePoll = () => { scheduled++; };
    global.api = async () => { const error = new Error('not found'); error.status = 404; throw error; };
    await panel.pollTask();
    assert(panel.task === null, '404 task was not cleared');
    assert(scheduled === 0, '404 task scheduled another poll');

    panel.task = { task_id: 'done', site_id: 7, component_type: 'core', task_kind: 'update', status: 'queued', stage: 'queued' };
    global.api = async () => ({ data: { task_id: 'done', site_id: 7, component_type: 'core', task_kind: 'update', status: 'success', stage: 'complete' } });
    await panel.pollTask();
    assert(panel.task.status === 'success', 'terminal task not retained for display');

    scheduled = 0;
    panel.task = null;
    const recent = new Date().toISOString();
    global.api = async () => ({ data: {
        task_id: 'latest', site_id: 7, component_type: 'core', task_kind: 'update', status: 'running', stage: 'updating_core',
        current_version: '7.0.1', target_version: '7.0.2', requested_at: recent
    } });
    const recovered = await panel.loadLatestTask({ preview: { current_version: '7.0.1', target_version: '7.0.2' }, since: Date.now() });
    assert(recovered === true && panel.task.task_id === 'latest', 'recent matching task was not recovered');
    assert(scheduled === 1, 'active recovered task was not scheduled');

    panel.stopPolling();
    panel.task = null;
    global.api = async () => ({ data: {
        task_id: 'old', site_id: 7, component_type: 'core', task_kind: 'update', status: 'success', stage: 'complete',
        current_version: '7.0.1', target_version: '7.0.2', requested_at: '2020-01-01T00:00:00Z'
    } });
    const stale = await panel.loadLatestTask({ preview: { current_version: '7.0.1', target_version: '7.0.2' }, since: Date.now() });
    assert(stale === false && panel.task === null, 'old matching task was accepted as confirmation recovery');

    global.api = async () => ({ data: {
        task_id: 'previous', site_id: 7, component_type: 'core', task_kind: 'update', status: 'success', stage: 'complete',
        current_version: '7.0.1', target_version: '7.0.2', requested_at: new Date().toISOString()
    } });
    const previous = await panel.loadLatestTask({ preview: { current_version: '7.0.1', target_version: '7.0.2' }, since: Date.now(), previousTaskID: 'previous' });
    assert(previous === false && panel.task === null, 'pre-existing task was accepted as confirmation recovery');

    for (const mismatch of [
        { id: 'wrong-current', current: '7.0.0', target: '7.0.2' },
        { id: 'wrong-target', current: '7.0.1', target: '7.0.3' },
    ]) {
        global.api = async () => ({ data: {
            task_id: mismatch.id, site_id: 7, component_type: 'core', task_kind: 'update', status: 'running', stage: 'updating_core',
            current_version: mismatch.current, target_version: mismatch.target, requested_at: new Date().toISOString()
        } });
        const versionMismatch = await panel.loadLatestTask({ preview: { current_version: '7.0.1', target_version: '7.0.2' }, since: Date.now() });
        assert(versionMismatch === false && panel.task === null, mismatch.id + ' task was accepted as confirmation recovery');
    }
})().catch(error => { console.error(error); process.exit(1); });
`)
	testScript := append(append([]byte{}, script...), harness...)
	scriptPath := filepath.Join(t.TempDir(), "wp-core-update-panel-behavior.js")
	if err := os.WriteFile(scriptPath, testScript, 0600); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command(node, scriptPath).CombinedOutput(); err != nil {
		t.Fatalf("core update panel behavior failed: %v\n%s", err, output)
	}
}

func TestAPIErrorPreservesHTTPStatus(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is not available")
	}
	app, err := os.ReadFile("../../web/js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	harness := []byte(`
global.window = { OLS_WPANEL_I18N: { lang: 'zh-CN', messages: {} }, location: {} };
global.document = {
    body: { dataset: { panelPrefix: '/panel' } },
    querySelector: () => ({ content: 'csrf' }),
};
global.fetch = async () => ({
    status: 404,
    ok: false,
    headers: { get: () => 'application/json' },
    json: async () => ({ success: false, message: 'not found' }),
});
api('/missing', { suppressToast: true }).then(
    () => { throw new Error('request unexpectedly succeeded'); },
    error => {
        if (error.status !== 404) throw new Error('HTTP status was not preserved');
    }
).catch(error => { console.error(error); process.exit(1); });
`)
	testScript := append(append([]byte{}, app...), harness...)
	scriptPath := filepath.Join(t.TempDir(), "api-status.js")
	if err := os.WriteFile(scriptPath, testScript, 0600); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command(node, scriptPath).CombinedOutput(); err != nil {
		t.Fatalf("API status behavior failed: %v\n%s", err, output)
	}
}

func TestRenderSafeMarkdownSupportsAIOutputWithoutHTMLInjection(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is not available")
	}
	app, err := os.ReadFile("../../web/js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	harness := []byte(`
const fence = String.fromCharCode(96, 96, 96);
const markdown = '# 标题\n\n| 项目 | 结果 |\n| --- | --- |\n| 状态 | **正常** |\n\n> 证据\n\n' + fence + '\n<unsafe>\n' + fence + '\n[安全链接](https://example.com) [危险链接](javascript:alert(1)) [反斜杠链接](/\\attacker.example/path) <img src=x onerror=alert(1)>';
const rendered = renderSafeMarkdown(markdown);
for (const expected of ['<h1', '<table', '<blockquote', '<pre', 'href="https://example.com"', '&lt;unsafe&gt;']) {
    if (!rendered.includes(expected)) throw new Error('missing Markdown output: ' + expected + '\n' + rendered);
}

for (const forbidden of ['href="javascript:', 'href="/\\attacker', '<img']) {
    if (rendered.includes(forbidden)) throw new Error('unsafe output retained: ' + forbidden + '\n' + rendered);
}
`)
	testScript := append(append([]byte{}, app...), harness...)
	scriptPath := filepath.Join(t.TempDir(), "safe-markdown.js")
	if err := os.WriteFile(scriptPath, testScript, 0600); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command(node, scriptPath).CombinedOutput(); err != nil {
		t.Fatalf("safe Markdown behavior failed: %v\n%s", err, output)
	}
}

func TestLegacyLogDetailAIEndpointIsRemoved(t *testing.T) {
	source, err := os.ReadFile("router.go")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(source, []byte(`/api/log-analysis/:id/details/ai`)) {
		t.Fatal("legacy log detail AI endpoint is still registered")
	}
}

func TestLogAnalysisUsesManualAIEntryWithPersistentProgress(t *testing.T) {
	template, err := os.ReadFile("../../web/templates/log_analysis.html")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range [][]byte{
		[]byte(`x-show="detailAILoading"`),
		[]byte(`log_analysis.ai_session_wait_help`),
		[]byte(`detailAILoading ? t('log_analysis.detail_ai_running') : t('log_analysis.continue_diagnosis')`),
	} {
		if !bytes.Contains(template, required) {
			t.Fatalf("log analysis AI progress UI missing %q", required)
		}
	}
	for _, forbidden := range [][]byte{[]byte(`x-model="useAI"`), []byte(`autoOpenAI`), []byte(`use_ai: this.useAI`)} {
		if bytes.Contains(template, forbidden) {
			t.Fatalf("log analysis still contains automatic AI entry %q", forbidden)
		}
	}
}

func TestWPInventoryPanelAPIContract(t *testing.T) {
	panel, err := os.ReadFile("../../web/templates/wp_inventory_panel.html")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range [][]byte{
		[]byte(`api('/websites/' + siteID + '/wp-inventory'`),
		[]byte(`api('/websites/' + siteID + '/wp-inventory/refresh', { method: 'POST'`),
		[]byte(`'/wp-inventory/tasks/' + encodeURIComponent(taskID)`),
		[]byte(`new URLSearchParams()`),
		[]byte(`params.set('page_size', String(state.pageSize))`),
		[]byte(`currentPage().total > currentPage().pageSize`),
		[]byte(`item.current_version || t('common.none')`),
		[]byte(`!item.network_active && !item.active && !item.current_theme`),
		[]byte(`if (tab === 'plugins') return 'plugin'`),
		[]byte(`if (tab === 'themes') return 'theme'`),
		[]byte(`this.componentUpdateAPI() + '/preview?component_key=' + encodeURIComponent(item.key)`),
		[]byte(`this.componentUpdateAPI() + '/confirm'`),
		[]byte(`this.componentUpdateAPI() + '/tasks/latest?component_key=' + encodeURIComponent(componentKey)`),
		[]byte(`this.componentUpdateAPI() + '/tasks/' + encodeURIComponent(taskID)`),
		[]byte(`confirmation_token: preview.confirmation_token`),
		[]byte(`target_version: preview.target_version`),
		[]byte(`database_backup_mode: this.pluginUpdate.databaseBackupMode`),
		[]byte(`signal: this.pluginUpdate.preparationController.signal`),
		[]byte(`cancelPluginPreparation()`),
		[]byte(`confirm: true`),
		[]byte(`pluginUpdate.preview?.current_theme === true && !pluginUpdate.riskAccepted`),
		[]byte(`timeout: 30 * 60 * 1000`),
		[]byte(`@click="selectTab('backups')"`),
		[]byte(`'/wp-update-backups'`),
		[]byte(`'/wp-update-backups/' + encodeURIComponent(backup.backup_id) + '/restore'`),
		[]byte(`'wp_update_backup.restore_confirm'`),
		[]byte(`'wp_update_backup.restore_batch_confirm'`),
		[]byte(`backup.batch_shared`),
		[]byte(`'wp_plugin_batch.rollback_reuse_confirm'`),
		[]byte(`this.invalidatePages();`),
		[]byte(`await this.loadSummary();`),
		[]byte(`setTimeout(() =>`),
	} {
		if !bytes.Contains(panel, required) {
			t.Fatalf("inventory panel is missing API contract %q", required)
		}
	}
	for _, forbidden := range [][]byte{
		[]byte(`setInterval(`),
		[]byte(`params.set('response'`),
		[]byte(`params.set('sort'`),
		[]byte(`params.set('order'`),
		[]byte(`params.set('column'`),
		[]byte(`params.set('collection_id'`),
		[]byte(`sessionStorage`),
		[]byte(`localStorage`),
		[]byte(`download_url`),
	} {
		if bytes.Contains(panel, forbidden) {
			t.Fatalf("inventory panel contains forbidden API behavior %q", forbidden)
		}
	}
}

func TestWPInventoryPanelBehavior(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is not available")
	}
	script := wpInventoryPanelScript(t)
	harness := []byte(`
function assert(condition, message) {
    if (!condition) throw new Error(message);
}
global.t = key => key;
global.fmtTime = value => String(value);
global.clearTimeout = id => { global.clearedTimer = id; };

(async () => {
    const panel = wpInventoryPanel();
    const summary = (status, successful) => ({
        site_id: 1,
        collection_status: status,
        has_successful_inventory: successful,
        wordpress: {},
        counts: {},
        active_task: null,
        last_error: null
    });

    panel.summary = summary('unknown', false);
    assert(panel.statusKey() === 'wp_inventory.status_unknown', 'unknown status');
    panel.summary = summary('complete', true);
    assert(panel.statusKey() === 'wp_inventory.status_complete', 'complete status');
    panel.summary = summary('failed', true);
    assert(panel.statusKey() === 'wp_inventory.status_failed_stale', 'failed stale status');
    panel.summary = summary('failed', false);
    assert(panel.statusKey() === 'wp_inventory.status_failed_empty', 'failed empty status');
    panel.summary.active_task = { id: 'queued', status: 'queued' };
    assert(panel.statusKey() === 'wp_inventory.status_queued', 'queued priority');
    panel.summary.active_task = { id: 'running', status: 'running' };
    assert(panel.statusKey() === 'wp_inventory.status_running', 'running priority');
    assert(panel.pollDelay(0) === 2000, 'initial poll delay');
    assert(panel.pollDelay(29999) === 2000, 'poll delay before 30 seconds');
    assert(panel.pollDelay(30000) === 5000, 'poll delay after 30 seconds');

    panel.pollTimer = 91;
    panel.stopPolling();
    assert(global.clearedTimer === 91 && panel.pollTimer === null, 'timer cleanup');
    assert(panel.errorKey({ code: 'future_error' }) === 'wp_inventory.error_unknown', 'unknown error fallback');
    assert(panel.errorKey({ code: 'memory_limit_exhausted' }) === 'wp_inventory.error_memory_limit', 'memory limit error key');
    assert(panel.errorKey({ code: 'runner_policy_mismatch' }) === 'wp_inventory.error_policy_mismatch', 'policy mismatch error key');
    assert(panel.errorKey({ code: 'wordpress_bootstrap_failed' }) === 'wp_inventory.error_bootstrap', 'bootstrap error key');
    assert(panel.errorKey({ code: 'wordpress_terminated' }) === 'wp_inventory.error_terminated', 'terminated error key');
    assert(panel.errorKey({ code: 'inventory_limit_exceeded' }) === 'wp_inventory.error_inventory_limit', 'inventory limit error key');
    assert(panel.errorKey({ code: 'runner_start_failed' }) === 'wp_inventory.error_start_failed', 'start failed error key');
	assert(panel.errorKey({ code: 'php_cli_unavailable' }) === 'wp_inventory.error_php_runtime', 'LSPHP runtime error key');
	assert(panel.errorKey({ code: 'invalid_site_path' }) === 'wp_inventory.error_site_path', 'site path error key');
	assert(panel.errorKey({ code: 'site_user_unavailable' }) === 'wp_inventory.error_site_user', 'site user error key');
	assert(panel.errorKey({ code: 'insufficient_privileges' }) === 'wp_inventory.error_permissions', 'permissions error key');
    assert(panel.retryHintKey({ code: 'memory_limit_exhausted' }) === 'wp_inventory.retry_useless', 'hard limit retry is useless');
    assert(panel.retryHintKey({ code: 'runner_timeout' }) === 'wp_inventory.retry_hint', 'transient error retry hint');
    panel.summary = { core_upgrade_available: false, counts: { plugin_updates: 0, theme_updates: 0 }, update_checks: { core: false, plugins: false, themes: false } };
    assert(panel.updatesOverallState() === 'unknown', 'no transients means unknown update status');
    panel.summary = { core_upgrade_available: false, counts: { plugin_updates: 0, theme_updates: 0 }, update_checks: { core: true, plugins: true, themes: true } };
    assert(panel.updatesOverallState() === 'up_to_date', 'all transients present with no updates means up to date');
    panel.summary = { core_upgrade_available: true, counts: { plugin_updates: 0, theme_updates: 0 }, update_checks: { core: true, plugins: true, themes: true } };
    assert(panel.updatesOverallState() === 'available', 'core upgrade available overrides');

    panel.siteID = 1;
    panel.requestGeneration = 7;
    panel.loadSummary = async () => {};
    await panel.setSite({ id: 2, site_type: 'wordpress' });
    assert(panel.siteID === 2, 'site switch');
    assert(panel.requestGeneration === 8, 'site switch invalidates old requests');

    panel.summary = summary('complete', true);
    panel.summary.site_id = 2;
    panel.summary.active_task = { id: 'task-id', site_id: 2, status: 'running' };
    panel.pages.plugins.page = 3;
    panel.pages.themes.page = 4;
    panel.pages.updates.page = 5;
    global.api = async () => ({ data: { id: 'task-id', site_id: 2, status: 'succeeded' } });
    await panel.pollTask('task-id');
    assert(panel.pages.plugins.page === 1, 'terminal task resets plugin page');
    assert(panel.pages.themes.page === 1, 'terminal task resets theme page');
    assert(panel.pages.updates.page === 1, 'terminal task resets update page');

    const candidate = { type: 'plugin', key: 'classic-editor/classic-editor.php', current_version: '1.6', target_version: '1.7' };
    assert(panel.canUpdatePlugin(candidate), 'official directory plugin candidate rejected');
    assert(!panel.canUpdatePlugin({ ...candidate, type: 'theme' }), 'theme candidate accepted by plugin updater');
    assert(!panel.canUpdatePlugin({ ...candidate, key: 'hello.php' }), 'unsupported single-file plugin accepted');

    panel.pluginUpdate.componentKey = candidate.key;
    panel.pluginUpdate.componentType = 'plugin';
    assert(panel.validPluginPreview({
        available: true, site_id: 2, component_key: candidate.key, current_version: '1.6', target_version: '1.7',
        confirmation_token: 'opaque', package_source: 'wordpress.org', verification_required: 'structure_only',
        database_backup: true, plugin_files_backup: true
    }), 'valid plugin preview rejected');
    assert(!panel.validPluginPreview({
        available: true, site_id: 1, component_key: candidate.key, current_version: '1.6', target_version: '1.7',
        confirmation_token: 'opaque', package_source: 'wordpress.org', verification_required: 'structure_only',
        database_backup: true, plugin_files_backup: true
    }), 'cross-site plugin preview accepted');
    const themeCandidate = { type: 'theme', key: 'twentytwentyfive', current_version: '1.4', target_version: '1.5' };
    assert(panel.canUpdateComponent(themeCandidate), 'official theme candidate rejected');
    panel.pluginUpdate.componentType = 'theme';
    panel.pluginUpdate.componentKey = themeCandidate.key;
    assert(panel.validPluginPreview({
        available: true, site_id: 2, component_key: themeCandidate.key, current_version: '1.4', target_version: '1.5',
        confirmation_token: 'opaque-theme', risk_token: 'risk', package_source: 'wordpress.org',
        verification_required: 'structure_only', database_backup: true, theme_files_backup: true,
        current_theme: true, template: ''
    }), 'valid current-theme preview rejected');
    panel.pluginUpdate.preview = {
        available: true, site_id: 2, component_key: themeCandidate.key, current_version: '1.4', target_version: '1.5',
        confirmation_token: 'opaque-theme', risk_token: 'risk', package_source: 'wordpress.org',
        verification_required: 'structure_only', database_backup: true, theme_files_backup: true,
        current_theme: true, template: ''
    };
    let themeConfirmCalls = 0;
    global.api = async () => { themeConfirmCalls++; throw new Error('confirm should be gated'); };
    await panel.confirmPluginUpdate();
    assert(themeConfirmCalls === 0, 'current theme update was submitted without explicit risk confirmation');
    panel.pluginUpdate.preview = null;
    panel.pluginUpdate.componentType = 'plugin';
    panel.pluginUpdate.componentKey = candidate.key;

    panel.pluginUpdate.task = {
        task_id: 'plugin-stale', site_id: 2, component_type: 'plugin', component_key: candidate.key,
        task_kind: 'update', status: 'queued', stage: 'queued'
    };
    let pluginScheduled = 0;
    panel.schedulePluginPoll = () => { pluginScheduled++; };
    global.api = async () => { const error = new Error('not found'); error.status = 404; throw error; };
    await panel.pollPluginTask();
    assert(panel.pluginUpdate.task === null, '404 plugin task was not cleared');
    assert(pluginScheduled === 0, '404 plugin task scheduled another poll');

    panel.pluginUpdate.task = {
        task_id: 'plugin-done', site_id: 2, component_type: 'plugin', component_key: candidate.key,
        task_kind: 'update', status: 'queued', stage: 'queued'
    };
    global.api = async () => ({ data: {
        task_id: 'plugin-done', site_id: 2, component_type: 'plugin', component_key: candidate.key,
        task_kind: 'update', status: 'success', stage: 'complete'
    } });
    await panel.pollPluginTask();
    assert(panel.pluginUpdate.task.status === 'success', 'terminal plugin task not retained');

    panel.pluginUpdate.task = null;
    global.api = async () => ({ data: {
        task_id: 'plugin-latest', site_id: 2, component_type: 'plugin', component_key: candidate.key,
        task_kind: 'update', status: 'running', stage: 'updating_component',
        current_version: '1.6', target_version: '1.7', requested_at: new Date().toISOString()
    } });
    const recovered = await panel.loadLatestPluginTask(candidate.key, {
        componentKey: candidate.key, currentVersion: '1.6', targetVersion: '1.7', since: Date.now(), previousTaskID: ''
    });
    assert(recovered === true && panel.pluginUpdate.task.task_id === 'plugin-latest', 'recent plugin task was not recovered');
    assert(pluginScheduled === 1, 'active recovered plugin task was not scheduled');
})().catch(error => {
    console.error(error);
    process.exit(1);
});
`)
	testScript := append(append([]byte{}, script...), harness...)
	scriptPath := filepath.Join(t.TempDir(), "wp-inventory-panel-behavior.js")
	if err := os.WriteFile(scriptPath, testScript, 0600); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command(node, scriptPath).CombinedOutput(); err != nil {
		t.Fatalf("inventory panel behavior failed: %v\n%s", err, output)
	}
}

func TestWPUSNoUntranslatedPlaceholders(t *testing.T) {
	content, err := os.ReadFile("../i18n/locales/en-US.json")
	if err != nil {
		t.Fatal(err)
	}
	var locale map[string]any
	if err := json.Unmarshal(content, &locale); err != nil {
		t.Fatal(err)
	}
	var walk func(prefix string, node any)
	walk = func(prefix string, node any) {
		switch v := node.(type) {
		case map[string]any:
			for key, child := range v {
				walk(prefix+"."+key, child)
			}
		case string:
			if strings.HasPrefix(v, "EN_TODO:") {
				t.Errorf("%s = %q is an untranslated placeholder", strings.TrimPrefix(prefix, "."), v)
			}
		}
	}
	walk("", locale)
}

func wpInventoryPanelScript(t *testing.T) []byte {
	t.Helper()
	rendered := renderPage(t, "wordpress_site_detail.html", "wordpress_site_detail_content")
	scriptPattern := regexp.MustCompile(`(?s)<script>(.*?)</script>`)
	for _, match := range scriptPattern.FindAllSubmatch(rendered, -1) {
		if bytes.Contains(match[1], []byte(`function wpInventoryPanel()`)) {
			return match[1]
		}
	}
	t.Fatal("rendered WordPress detail is missing the inventory panel script")
	return nil
}

func TestDatabaseManagementRoutesRegistered(t *testing.T) {
	source, err := os.ReadFile("router.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, route := range []string{
		`protected.GET("/api/databases", databaseManagerHandler.List)`,
		`protected.GET("/databases", func(c *gin.Context)`,
		`protected.GET("/databases/:id", func(c *gin.Context)`,
	} {
		if !bytes.Contains(source, []byte(route)) {
			t.Fatalf("router.go missing route %s", route)
		}
	}
}

func TestWebsiteDetailCardOrderAndDatabaseNavigation(t *testing.T) {
	source, err := os.ReadFile("../../web/templates/website_detail.html")
	if err != nil {
		t.Fatal(err)
	}
	for _, partial := range []string{"site_security_summary", "wordpress_cache_status"} {
		content, err := os.ReadFile("../../web/templates/" + partial + ".html")
		if err != nil {
			t.Fatal(err)
		}
		source = bytes.ReplaceAll(source, []byte(`{{template "`+partial+`" .}}`), content)
	}
	overviewStart := bytes.Index(source, []byte(`<div id="site-overview"`))
	cacheStart := bytes.Index(source, []byte(`<div id="site-performance"`))
	securityStart := bytes.Index(source, []byte(`<section id="site-security"`))
	logsStart := bytes.Index(source, []byte(`<div id="site-logs"`))
	if overviewStart < 0 || cacheStart <= overviewStart || securityStart <= cacheStart || logsStart <= securityStart {
		t.Fatalf("website workspaces missing or out of order: overview=%d cache=%d security=%d logs=%d", overviewStart, cacheStart, securityStart, logsStart)
	}
	overview := source[overviewStart:cacheStart]
	if !bytes.Contains(overview, []byte(`id="site-ssl"`)) || !bytes.Contains(overview, []byte(`website.ssl_management`)) {
		t.Fatal("runtime overview is missing its SSL management card")
	}
	if bytes.Contains(overview, []byte(`website.site_monitoring`)) {
		t.Fatal("monitoring controls must live in the independent website security workspace")
	}
	security := source[securityStart:logsStart]
	previous := -1
	for _, card := range [][]byte{
		[]byte(`website.security_status_title`),
		[]byte(`website.security_wp_policy`),
		[]byte(`website.site_monitoring`),
		[]byte(`website.security_recovery`),
		[]byte(`id="site-protection"`),
	} {
		position := bytes.Index(security, card)
		if position <= previous {
			t.Fatalf("website security card %s is missing or out of order", card)
		}
		previous = position
	}
	for _, required := range [][]byte{
		[]byte(`x-show="detailTab === 'security'"`),
		[]byte(`@click="fetchSiteSecurityStatus()"`),
		[]byte(`@click="saveSiteSecurityPolicy()"`),
		[]byte(`@click="saveMonitoring()"`),
		[]byte(`@click="verifySummaryCheck(key)"`),
		[]byte(`name="site-security-evidence"`),
		[]byte(`/databases/' + site.id`),
	} {
		if !bytes.Contains(security, required) {
			t.Fatalf("website security workspace missing control %q", required)
		}
	}
	for _, action := range []struct {
		click string
		show  string
	}{
		{`verifySummaryCheck(key)`, `summaryCheck(key).can_verify`},
		{`openSummarySettings(key)`, `!summaryCheck(key).can_verify && summarySettingsAvailable(key)`},
	} {
		buttons := regexp.MustCompile(`<button\b[^>]*@click="` + regexp.QuoteMeta(action.click) + `"[^>]*>`).FindAll(security, -1)
		if len(buttons) != 1 {
			t.Fatalf("compact security summary must have exactly one %s action, got %d", action.click, len(buttons))
		}
		if bytes.Count(buttons[0], []byte(`x-show="`)) != 1 || !bytes.Contains(buttons[0], []byte(`x-show="`+action.show+`"`)) {
			t.Fatalf("compact security summary action %s must use its mutually exclusive can_verify guard", action.click)
		}
	}
	if bytes.Contains(source, []byte(`website.openlitespeed_custom_config`)) {
		t.Fatal("website detail still exposes the disabled OpenLiteSpeed custom configuration card")
	}
	if !bytes.Contains(source, []byte(`'/databases/' + site.id`)) {
		t.Fatal("website detail is missing the direct database management link")
	}
	for _, required := range [][]byte{
		[]byte(`@click="setDetailTab('overview')"`),
		[]byte(`@click="setDetailTab('cache')"`),
		[]byte(`@click="setDetailTab('security')"`),
		[]byte(`@click="setDetailTab('logs')"`),
		[]byte(`x-show="detailTab === 'cache'"`),
		[]byte(`x-show="detailTab === 'security' && site.site_type === 'wordpress'"`),
		[]byte(`api('/websites/' + siteID + '/security-status'`),
	} {
		if !bytes.Contains(source, required) {
			t.Fatalf("website detail tab layout is missing %q", required)
		}
	}
	for _, required := range [][]byte{
		[]byte(`website.performance_cache`),
		[]byte(`cacheRuntime.plugin_status`),
		[]byte(`cacheRuntime.redis_object_cache_configured`),
		[]byte(`/litespeed-cache/migrate`),
		[]byte(`/redis-object-cache`),
		[]byte(`/wp-admin/admin.php?page=litespeed-cache#object`),
	} {
		if !bytes.Contains(source, required) {
			t.Fatalf("website detail cache workspace is missing %q", required)
		}
	}
}

func TestWebsiteCanonicalDomainAndDetailLayoutControls(t *testing.T) {
	createSource, err := os.ReadFile("../../web/templates/website_new.html")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range [][]byte{
		[]byte(`@click="addWWWRedirect()"`),
		[]byte(`:disabled="!aliases.trim()"`),
		[]byte(`alias_redirect_mode: this.aliasRedirectMode`),
		[]byte(`this.aliasRedirectMode = '301'`),
	} {
		if !bytes.Contains(createSource, required) {
			t.Fatalf("website create canonical-domain UI is missing %q", required)
		}
	}
	if bytes.Contains(createSource, []byte(`<div x-show="aliases.trim()"`)) {
		t.Fatal("website create still hides the entire alias handling control")
	}

	detailSource, err := os.ReadFile("../../web/templates/website_detail.html")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range [][]byte{
		[]byte(`@click="addEditedWWWRedirect()"`),
		[]byte(`@click="openWWWRedirectModal()"`),
		[]byte(`this.editAliasRedirectMode = '301'`),
		[]byte(`this.reissueSSL = true`),
		[]byte(`id="site-overview"`),
		[]byte(`id="site-performance"`),
		[]byte(`id="site-protection"`),
		[]byte(`id="site-logs"`),
		[]byte(`@click="setDetailTab('overview')"`),
		[]byte(`@click="setDetailTab('cache')"`),
		[]byte(`@click="setDetailTab('security')"`),
		[]byte(`@click="setDetailTab('logs')"`),
		[]byte(`'security-maintenance': 'security'`),
		[]byte(`await Promise.all([this.fetchLogs(), this.fetchLogFiles()])`),
		[]byte(`website.wordpress_cache_owner_notice`),
		[]byte(`website.manage_php_memory`),
	} {
		if !bytes.Contains(detailSource, required) {
			t.Fatalf("website detail canonical-domain/layout UI is missing %q", required)
		}
	}
}

func TestSidebarNavigationOrder(t *testing.T) {
	source, err := os.ReadFile("../../web/templates/base.html")
	if err != nil {
		t.Fatal(err)
	}
	items := [][]byte{
		[]byte(`href="/{{$.RandomSuffix}}/"`),
		[]byte(`href="/{{$.RandomSuffix}}/websites"`),
		[]byte(`href="/{{$.RandomSuffix}}/files"`),
		[]byte(`href="/{{$.RandomSuffix}}/databases"`),
		[]byte(`href="/{{$.RandomSuffix}}/backups"`),
		[]byte(`href="/{{$.RandomSuffix}}/cron"`),
		[]byte(`href="/{{$.RandomSuffix}}/firewall"`),
		[]byte(`href="/{{$.RandomSuffix}}/security"`),
		[]byte(`href="/{{$.RandomSuffix}}/software"`),
		[]byte(`href="/{{$.RandomSuffix}}/alert"`),
		[]byte(`href="/{{$.RandomSuffix}}/ai-diagnostics"`),
		[]byte(`href="/{{$.RandomSuffix}}/vps"`),
		[]byte(`href="/{{$.RandomSuffix}}/settings"`),
		[]byte(`href="/{{$.RandomSuffix}}/help"`),
	}
	previous := -1
	for _, item := range items {
		position := bytes.Index(source, item)
		if position < 0 || position <= previous {
			t.Fatalf("sidebar item %s is missing or out of order", item)
		}
		previous = position
	}
}

func TestPanelLightWorkspaceAndDarkSidebar(t *testing.T) {
	source, err := os.ReadFile("../../web/templates/base.html")
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"toggleTheme", "ols-wpanel-theme", "theme.label"} {
		if bytes.Contains(source, []byte(forbidden)) {
			t.Fatalf("removed appearance control remains: %s", forbidden)
		}
	}
	for _, lang := range []string{"zh-CN", "en-US"} {
		t.Run(lang, func(t *testing.T) {
			data := testPageData("dashboard_content")
			data["Lang"] = lang
			data["MessagesJSON"] = i18n.MessagesJSON(lang, i18nKeys)
			data["CSRFToken"] = "shell-csrf-proof"
			var output bytes.Buffer
			if err := parseTemplates(t).ExecuteTemplate(&output, "dashboard.html", data); err != nil {
				t.Fatal(err)
			}
			for _, required := range []string{
				`<html lang="` + lang + `" data-theme="light">`,
				`<meta name="csrf-token" content="shell-csrf-proof">`,
				`data-panel-prefix="/test" data-lang="` + lang + `"`,
				`class="panel-workspace"`, `class="panel-sidebar `,
				`href="#panel-main"`, `id="panel-main" class="panel-main" tabindex="-1"`,
				`aria-controls="panel-sidebar"`, `href="?lang=zh-CN"`, `href="?lang=en-US"`,
				i18n.T(lang, "nav.skip_content"), i18n.T(lang, "nav.menu"),
			} {
				if !strings.Contains(output.String(), required) {
					t.Fatalf("rendered %s workspace is missing %q", lang, required)
				}
			}
			previous := -1
			for _, asset := range []string{"main.css", "palette.css", "theme.css", "overview.css"} {
				link := `href="/test/assets/css/` + asset + `?v=test"`
				position := strings.Index(output.String(), link)
				if strings.Count(output.String(), link) != 1 || position <= previous {
					t.Fatalf("stylesheet %s must load once in cascade order", asset)
				}
				previous = position
			}
		})
	}
	css, err := os.ReadFile("../../web/css/theme.css")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"color-scheme: light", "background: var(--panel-bg)", "background: var(--panel-sidebar)", ":focus-visible", ".panel-skip-link:focus"} {
		if !bytes.Contains(css, []byte(required)) {
			t.Fatalf("workspace theme is missing %q", required)
		}
	}
	// Assert the intended light/dark contrast without fixing a specific palette.
	brightness := func(token string) float64 {
		t.Helper()
		match := regexp.MustCompile(regexp.QuoteMeta(token) + `:\s*#([0-9a-fA-F]{6})\s*;`).FindSubmatch(css)
		if len(match) != 2 {
			t.Fatalf("missing six-digit color token %s", token)
		}
		var value uint32
		if _, err := fmt.Sscanf(string(match[1]), "%x", &value); err != nil {
			t.Fatal(err)
		}
		return (float64(value>>16)*0.2126 + float64(value>>8&255)*0.7152 + float64(value&255)*0.0722) / 255
	}
	if brightness("--panel-bg") < 0.8 || brightness("--panel-sidebar") > 0.3 {
		t.Fatal("workspace must stay light and navigation must stay dark")
	}
	compiled, err := os.ReadFile("../../web/css/main.css")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{`.lg\:hidden`, `.lg\:static`, `.fixed`, `.flex`} {
		if !bytes.Contains(compiled, []byte(required)) {
			t.Fatalf("compiled Tailwind shell utility is missing %s", required)
		}
	}
}

func TestPanelMobileSidebarStateAndFocusTransitions(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is not available")
	}
	rendered := renderPage(t, "dashboard.html", "dashboard_content")
	bindings := map[string]string{}
	for _, attribute := range []string{"x-data", "@resize.window", "@keydown.escape.window", ":inert", ":aria-expanded"} {
		match := regexp.MustCompile(regexp.QuoteMeta(attribute) + `="([^"]*)"`).FindSubmatch(rendered)
		if len(match) != 2 {
			t.Fatalf("rendered shell is missing %s", attribute)
		}
		bindings[attribute] = html.UnescapeString(string(match[1]))
	}
	encoded, err := json.Marshal(bindings)
	if err != nil {
		t.Fatal(err)
	}
	harness := `
const assert = require('node:assert/strict');
const bindings = ` + string(encoded) + `;
global.window = { innerWidth: 390 };
const shell = new Function('return (' + bindings['x-data'] + ')')();
let sidebarFocus = 0, toggleFocus = 0;
shell.$nextTick = callback => callback();
shell.$refs = {
    sidebar: { querySelector: selector => { assert.equal(selector, 'a'); return { focus: () => sidebarFocus++ }; } },
    menuToggle: { focus: () => toggleFocus++ },
};
const expression = key => new Function('state', 'with(state) { return (' + bindings[key] + '); }')(shell);
const event = key => new Function('state', 'with(state) { ' + bindings[key] + '; }')(shell);
assert.equal(shell.sidebarOpen, false, 'mobile navigation starts closed');
assert.equal(expression(':inert'), false, 'mobile content starts interactive');
shell.toggleSidebar();
assert.equal(expression(':aria-expanded'), 'true');
assert.equal(expression(':inert'), true, 'open mobile navigation blocks content focus');
assert.equal(sidebarFocus, 1, 'opening navigation focuses its first link');
event('@keydown.escape.window');
assert.equal(shell.sidebarOpen, false);
assert.equal(expression(':inert'), false);
assert.equal(toggleFocus, 1, 'Escape restores focus to the menu button');
shell.toggleSidebar();
window.innerWidth = 1440;
event('@resize.window');
assert.equal(shell.sidebarOpen, true, 'desktop navigation remains open');
assert.equal(expression(':inert'), false, 'mobile-to-desktop resize releases main content');
event('@keydown.escape.window');
assert.equal(shell.sidebarOpen, true, 'desktop Escape does not hide persistent navigation');
assert.equal(toggleFocus, 1, 'desktop Escape does not steal focus');
window.innerWidth = 375;
event('@resize.window');
assert.equal(shell.sidebarOpen, false, 'desktop-to-mobile resize closes navigation');
assert.equal(expression(':aria-expanded'), 'false');
assert.equal(expression(':inert'), false);
`
	scriptPath := filepath.Join(t.TempDir(), "panel-sidebar-behavior.js")
	if err := os.WriteFile(scriptPath, []byte(harness), 0600); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command(node, scriptPath).CombinedOutput(); err != nil {
		t.Fatalf("panel sidebar behavior failed: %v\n%s", err, output)
	}
}

func TestWebsiteCreationOmitsExtensionCatalog(t *testing.T) {
	for _, path := range []string{"../../web/templates/website_new.html", "../../web/templates/websites.html"} {
		source, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, forbidden := range [][]byte{[]byte(`api('/extensions')`), []byte(`website.install_themes`), []byte(`website.install_plugins`), []byte(`enable_redis_cache`)} {
			if bytes.Contains(source, forbidden) {
				t.Fatalf("%s still contains removed extension catalog UI %q", path, forbidden)
			}
		}
	}
}

func TestCronPageExplainsManagedAndAutomaticTasks(t *testing.T) {
	source, err := os.ReadFile("../../web/templates/cron.html")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range [][]byte{
		[]byte(`cron.system_jobs_help`),
		[]byte(`cron.overview_help`),
		[]byte(`cron.task_type_wp_cron`),
		[]byte(`this.form.cron_expression = '*/5 * * * *'`),
	} {
		if !bytes.Contains(source, required) {
			t.Fatalf("cron guidance is missing %q", required)
		}
	}
}

func TestVPSPageIsReadOnlyAndKeepsFirewallDeepLinks(t *testing.T) {
	source, err := os.ReadFile("../../web/templates/vps.html")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range [][]byte{[]byte(`api('/vps/overview')`), []byte(`addresses(4)`), []byte(`addresses(6)`), []byte(`vps.terminal_maintenance`), []byte(`vps.dns_readonly_help`), []byte(`vps.swap_readonly_help`)} {
		if !bytes.Contains(source, required) {
			t.Fatalf("read-only server page is missing %q", required)
		}
	}
	for _, forbidden := range [][]byte{[]byte(`tab='maintenance'`), []byte(`applyDNS`), []byte(`testDNS`), []byte(`saveCustomSwap`), []byte(`removeManagedSwap`), []byte(`enableNftablesBoot`), []byte(`method: 'POST'`), []byte(`method: 'PUT'`), []byte(`method: 'DELETE'`), []byte(`resource_snapshot`)} {
		if bytes.Contains(source, forbidden) {
			t.Fatalf("read-only server page still contains %q", forbidden)
		}
	}
	routes, err := os.ReadFile("router.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, method := range []string{"POST", "PUT", "DELETE", "PATCH"} {
		if bytes.Contains(routes, []byte(`protected.`+method+`("/api/vps/`)) {
			t.Fatalf("VPS mutation route remains registered for %s", method)
		}
	}

	firewall, err := os.ReadFile("../../web/templates/firewall.html")
	if err != nil {
		t.Fatal(err)
	}
	controller, err := os.ReadFile("../../web/templates/firewall_controller.html")
	if err != nil {
		t.Fatal(err)
	}
	ports, err := os.ReadFile("../../web/templates/firewall_ports.html")
	if err != nil {
		t.Fatal(err)
	}
	access, err := os.ReadFile("../../web/templates/firewall_access.html")
	if err != nil {
		t.Fatal(err)
	}
	firewall = append(append(append(firewall, controller...), ports...), access...)
	if !bytes.Contains(firewall, []byte(`new URLSearchParams(window.location.search).get('tab')`)) {
		t.Fatal("firewall page does not honor the VPS management ports deep link")
	}
	for _, required := range [][]byte{
		[]byte(`source_mode: 'current'`),
		[]byte(`duration_mode: 'permanent'`),
		[]byte(`firewall.scope_specific`),
		[]byte(`firewall.access_closed`),
		[]byte(`firewall.access_everyone`),
		[]byte(`firewall.confirm_any_source`),
		[]byte(`'/firewall/ports/access/preview'`),
		[]byte(`'/firewall/ports/access/apply'`),
		[]byte(`'/firewall/ports/access/confirm'`),
		[]byte(`listener.address`),
		[]byte(`rule.hit_packets`),
		[]byte(`rule.created_at`),
		[]byte(`rule.expires_at`),
	} {
		if !bytes.Contains(firewall, required) {
			t.Fatalf("firewall ports UI is missing %q", required)
		}
	}
}

func TestDatabaseDetailShowsFiveRecentBackupsByDefault(t *testing.T) {
	source, err := os.ReadFile("../../web/templates/database_detail.html")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(source, []byte(`this.backups.slice(0, 5)`)) {
		t.Fatal("database detail does not limit the default backup list to five entries")
	}
}

func TestDatabaseRestoreShowsLongRunningStatusAndBlocksConflictingActions(t *testing.T) {
	source, err := os.ReadFile("../../web/templates/database_detail.html")
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range [][]byte{
		[]byte(`restoreStatusLabel()`),
		[]byte(`restoreElapsedSeconds`),
		[]byte(`website.restore_long_running_help`),
		[]byte(`website.restore_success_elapsed`),
		[]byte(`backupSubmitting || restoreBusy()`),
		[]byte(`dbSubmitting || restoreBusy()`),
		[]byte(`if (r.data?.status === 'running') this.restorePhase = 'running'`),
	} {
		if !bytes.Contains(source, expected) {
			t.Fatalf("database restore progress UI is missing %s", expected)
		}
	}
}

func TestDatabaseDetailProvidesWordPressAdministratorEditor(t *testing.T) {
	templateSource, err := os.ReadFile("../../web/templates/database_detail.html")
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range [][]byte{
		[]byte(`@click="openAdminModal()"`),
		[]byte(`'/wp-administrators'`),
		[]byte(`sync_nicename:`),
		[]byte(`sync_admin_email:`),
		[]byte(`destroy_sessions:`),
		[]byte(`crypto.getRandomValues(values)`),
	} {
		if !bytes.Contains(templateSource, expected) {
			t.Fatalf("database detail administrator editor is missing %s", expected)
		}
	}
	routerSource, err := os.ReadFile("router.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range [][]byte{
		[]byte(`protected.GET("/api/websites/:id/wp-administrators", websiteHandler.ListWPAdministrators)`),
		[]byte(`protected.PUT("/api/websites/:id/wp-administrators", websiteHandler.UpdateWPAdministrator)`),
	} {
		if !bytes.Contains(routerSource, expected) {
			t.Fatalf("administrator route is missing %s", expected)
		}
	}
}

func TestFileManagerStartsWithDirectoryList(t *testing.T) {
	source, err := os.ReadFile("../../web/templates/files.html")
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range [][]byte{
		[]byte(`x-model.trim="siteSearch"`),
		[]byte(`@click="openRoot(site.id)"`),
		[]byte(`@click="openRoot(0)"`),
		[]byte(`@click="showRootList()"`),
		[]byte(`url.searchParams.set('site_id', this.selectedSite)`),
		[]byte(`calculateDirectorySize(siteID, path)`),
		[]byte(`'/files/size?site_id='`),
		[]byte(`{ timeout: 65000, suppressToast: true }`),
		[]byte(`deepLinkFailed: false`),
		[]byte(`this.deepLinkFailed = true`),
		[]byte(`class="badge-success text-xs">{{t .Lang "files.protected"}}`),
		[]byte(`class="badge-warning text-xs">{{t .Lang "files.not_protected"}}`),
		[]byte(`{{t .Lang "files.manage_protection"}}`),
		[]byte(`'/websites/' + site.id + '#security-maintenance'`),
	} {
		if !bytes.Contains(source, expected) {
			t.Fatalf("file manager is missing directory-list behavior %s", expected)
		}
	}
	if bytes.Contains(source, []byte(`x-model="selectedSite"`)) {
		t.Fatal("file manager still requires the website dropdown")
	}
	if bytes.Contains(source, []byte(`:disabled="directorySizeState`)) {
		t.Fatal("directory size buttons must remain recoverable while a request is in progress")
	}
	if bytes.Contains(source, []byte(`x-show="!siteSearch"`)) {
		t.Fatal("file manager hides the backup directory while filtering websites")
	}
}

func TestDirectorySizeRouteRegistered(t *testing.T) {
	source, err := os.ReadFile("router.go")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(source, []byte(`protected.GET("/api/files/size", fileHandler.DirectorySize)`)) {
		t.Fatal("directory size route is not registered")
	}
}

func TestFileSearchRouteAndInterfaceAreRegistered(t *testing.T) {
	routerSource, err := os.ReadFile("router.go")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(routerSource, []byte(`protected.GET("/api/files/search", fileHandler.Search)`)) {
		t.Fatal("file search route is not registered")
	}
	templateSource, err := os.ReadFile("../../web/templates/files.html")
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range [][]byte{
		[]byte(`x-model.trim="search.query"`),
		[]byte(`x-model="search.scope"`),
		[]byte(`'/files/search?site_id='`),
		[]byte(`@click="goPage(1)"`),
		[]byte(`@click="goPage(totalPages)"`),
		[]byte(`downloadPath(f.path)`),
	} {
		if !bytes.Contains(templateSource, expected) {
			t.Fatalf("file search interface is missing %s", expected)
		}
	}
}

func TestPageTitleKeysExist(t *testing.T) {
	for active, key := range pageTitleKeys {
		t.Run(active, func(t *testing.T) {
			if got := i18n.T(i18n.DefaultLang, key); got == key {
				t.Fatalf("missing zh-CN page title key %q", key)
			}
			if got := i18n.T(i18n.English, key); got == key {
				t.Fatalf("missing en-US page title key %q", key)
			}
		})
	}
}

func renderPage(t *testing.T, page, content string) []byte {
	t.Helper()
	data := testPageData(content)
	var output bytes.Buffer
	if err := parseTemplates(t).ExecuteTemplate(&output, page, data); err != nil {
		t.Fatalf("render %s: %v", page, err)
	}
	return output.Bytes()
}

func testPageData(content string) map[string]any {
	return map[string]any{
		"Title":           "Test",
		"PanelTitle":      "OLS WPanel",
		"PanelVersion":    "test",
		"AssetVersion":    "test",
		"ContentTemplate": content,
		"RandomSuffix":    "test",
		"Active":          "dashboard",
		"AssetPrefix":     "/test/assets",
		"CSRFToken":       "test",
		"Lang":            i18n.DefaultLang,
		"MessagesJSON":    i18n.MessagesJSON(i18n.DefaultLang, i18nKeys),
	}
}

func parseTemplates(t *testing.T) *template.Template {
	t.Helper()
	return template.Must(template.New("").Funcs(i18n.FuncMap()).ParseFS(os.DirFS("../../web"), "templates/*.html"))
}
