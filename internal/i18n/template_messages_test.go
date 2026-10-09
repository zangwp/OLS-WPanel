package i18n

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
	"testing/fstest"
)

func decodeTemplateMessages(t *testing.T, raw string) map[string]string {
	t.Helper()
	var result map[string]string
	if err := json.Unmarshal([]byte(raw), &result); err != nil {
		t.Fatalf("invalid translation JSON: %v", err)
	}
	return result
}

func TestTemplateMessagesFollowsPartialsDynamicKeysAndCyclesWithoutBaseDispatcher(t *testing.T) {
	files := fstest.MapFS{
		"templates/base.html":          {Data: []byte(`{{define "base"}}{{t .Lang "nav.dashboard"}}{{template "page_content" .}}{{template "other_content" .}}{{end}}`)},
		"templates/page.html":          {Data: []byte(`{{template "base" .}}{{define "page_content"}}<button x-text="t('website.status_' + state)"></button>{{template "shared" .}}{{template "access_script" .}}{{end}}`)},
		"templates/shared.html":        {Data: []byte(`{{define "shared"}}<span x-text="t('site_security.state_' + state)"></span>{{template "loop" .}}{{end}}{{define "loop"}}{{template "shared" .}}{{end}}`)},
		"templates/access_script.html": {Data: []byte("{{define \"access_script\"}}<script>const label=t(`wp_access.reason_${reason}`)</script>{{end}}")},
		"templates/other.html":         {Data: []byte(`{{template "base" .}}{{define "other_content"}}<span x-text="t('software.title')"></span>{{end}}`)},
		"templates/login.html":         {Data: []byte(`<span>{{t .Lang "auth.login"}}</span>`)},
	}
	keys := []string{"common.loading", "auth.login", "nav.dashboard", "app.tagline", "dashboard.close", "dashboard.title", "website.status_running", "website.status_paused", "site_security.state_effective", "wp_access.reason_https_required", "software.title"}
	catalog, err := NewTemplateMessages(files, keys)
	if err != nil {
		t.Fatal(err)
	}
	page := decodeTemplateMessages(t, string(catalog.JSON(English, "page_content")))
	for _, key := range []string{"common.loading", "auth.login", "nav.dashboard", "app.tagline", "dashboard.close", "website.status_running", "website.status_paused", "site_security.state_effective", "wp_access.reason_https_required"} {
		if _, ok := page[key]; !ok {
			t.Fatalf("partial/dynamic/shared key omitted: %s", key)
		}
	}
	for _, key := range []string{"software.title", "dashboard.title"} {
		if _, ok := page[key]; ok {
			t.Fatalf("base dispatcher imported unrelated page: %s", key)
		}
	}
	if string(catalog.JSON(English, "page")) != string(catalog.JSON(English, "page_content")) {
		t.Fatal("filename alias lost its content definition")
	}
	if string(catalog.JSON(English, "login")) != string(catalog.JSON(English, "login.html")) {
		t.Fatal("standalone login alias is missing")
	}
	login := decodeTemplateMessages(t, string(catalog.JSON(English, "login")))
	if _, ok := login["website.status_running"]; ok {
		t.Fatal("login inherited the website page")
	}
	fallback := decodeTemplateMessages(t, string(catalog.JSON(English, "unknown_page")))
	if len(fallback) != len(keys) || fallback["software.title"] != T(English, "software.title") {
		t.Fatal("unknown page did not keep the full allowlist")
	}
	if string(catalog.JSON("invalid-language", "page_content")) != string(catalog.JSON(DefaultLang, "page_content")) {
		t.Fatal("locale fallback changed")
	}
}

func TestTemplateMessagesEscapesInlineJavaScriptAndSnapshotsTranslations(t *testing.T) {
	original := messages
	messages = map[string]map[string]any{DefaultLang: {"sample": map[string]any{"value": "</script><script>alert('x')</script>&\u2028\u2029"}}, English: {"sample": map[string]any{"value": "English <message>"}}}
	t.Cleanup(func() { messages = original })
	files := fstest.MapFS{"page.html": {Data: []byte(`{{define "page_content"}}<p x-text="t('sample.value')"></p><input value="RAW_CREDENTIAL_PLACEHOLDER">{{end}}`)}}
	keys := []string{"sample.value"}
	catalog, err := NewTemplateMessages(files, keys)
	if err != nil {
		t.Fatal(err)
	}
	raw := string(catalog.JSON(DefaultLang, "page_content"))
	for _, danger := range []string{"</script>", "<script>", "&", "\u2028", "\u2029", "RAW_CREDENTIAL_PLACEHOLDER"} {
		if strings.Contains(raw, danger) {
			t.Fatalf("unsafe script/source content escaped incorrectly: %q", danger)
		}
	}
	if got := decodeTemplateMessages(t, raw)["sample.value"]; got != T(DefaultLang, "sample.value") {
		t.Fatal("escaping changed the translated value")
	}
	keys[0] = "unrelated.key"
	messages[DefaultLang]["sample"].(map[string]any)["value"] = "changed after startup"
	if got := string(catalog.JSON(DefaultLang, "page_content")); got != raw {
		t.Fatal("request path did not use the immutable precomputed translation snapshot")
	}
	if english := decodeTemplateMessages(t, string(catalog.JSON(English, "page_content")))["sample.value"]; english != "English <message>" {
		t.Fatalf("English catalog=%q", english)
	}
}

func TestTemplateMessagesActualPagesReducePayloadAndKeepComponentNamespaces(t *testing.T) {
	var keys []string
	var flatten func(string, map[string]any)
	flatten = func(prefix string, values map[string]any) {
		for name, value := range values {
			key := name
			if prefix != "" {
				key = prefix + "." + name
			}
			switch value := value.(type) {
			case string:
				keys = append(keys, key)
			case map[string]any:
				flatten(key, value)
			}
		}
	}
	flatten("", messages[DefaultLang])
	catalog, err := NewTemplateMessages(os.DirFS("../../web"), keys)
	if err != nil {
		t.Fatal(err)
	}
	for _, lang := range []string{DefaultLang, English} {
		full := string(catalog.JSON(lang, "unknown_content"))
		for _, page := range []string{"login", "settings_content", "websites_content", "websites_detail_content", "security_content"} {
			payload := string(catalog.JSON(lang, page))
			if len(payload) >= len(full) {
				t.Fatalf("%s %s still sends full catalog: %d/%d bytes", lang, page, len(payload), len(full))
			}
			t.Logf("%s %s: %d/%d bytes", lang, page, len(payload), len(full))
		}
		if len(catalog.JSON(lang, "login")) >= len(full)/3 {
			t.Fatal("standalone login payload was not substantially reduced")
		}
		detail := decodeTemplateMessages(t, string(catalog.JSON(lang, "websites_detail_content")))
		for _, key := range []string{"wp_access.title", "site_security.summary_help", "anomaly.title"} {
			if _, ok := detail[key]; !ok {
				t.Fatalf("actual website partial namespace missing %s", key)
			}
		}
	}
}

func TestTemplateMessagesRejectsUnreadableOrMalformedInputs(t *testing.T) {
	for _, files := range []fstest.MapFS{{}, {"bad.html": {Data: []byte(`{{define "bad"}}`)}}} {
		if _, err := NewTemplateMessages(files, nil); err == nil {
			t.Fatal("invalid template catalog was accepted")
		}
	}
	if _, err := NewTemplateMessages(nil, nil); err == nil {
		t.Fatal("nil filesystem accepted")
	}
	var catalog *TemplateMessages
	if got := decodeTemplateMessages(t, string(catalog.JSON(English, "unknown"))); !reflect.DeepEqual(got, map[string]string{}) {
		t.Fatal("nil catalog unsafe fallback")
	}
}
