package i18n

import (
	"encoding/json"
	"os"
	"regexp"
	"testing"
)

func TestWebsiteSecurityVerificationTranslationsReachPageCatalog(t *testing.T) {
	routerSource, err := os.ReadFile("../router/router.go")
	if err != nil {
		t.Fatal(err)
	}
	declaration := regexp.MustCompile(`(?s)var i18nKeys = \[\]string\{(.*?)\n\}`).FindSubmatch(routerSource)
	if len(declaration) != 2 {
		t.Fatal("router translation allowlist declaration was not found")
	}
	var exposedKeys []string
	for _, match := range regexp.MustCompile(`"([a-zA-Z][a-zA-Z0-9_]*\.[a-zA-Z0-9_]+)"`).FindAllSubmatch(declaration[1], -1) {
		exposedKeys = append(exposedKeys, string(match[1]))
	}
	catalog, err := NewTemplateMessages(os.DirFS("../../web"), exposedKeys)
	if err != nil {
		t.Fatal(err)
	}
	keys := []string{
		"site_security.verification_save_failed",
		"site_security.verification_history_unavailable",
		"site_security.last_verification",
		"site_security.last_verification_evidence",
		"site_security.verification_applicability",
		"site_security.history_never_checked",
		"site_security.history_passed",
		"site_security.history_ready",
		"site_security.history_failed",
		"site_security.history_incomplete",
		"site_security.history_configuration_changed",
		"site_security.history_configuration_unavailable",
		"site_security.verification_result_passed",
		"site_security.verification_result_ready",
		"site_security.verification_result_failed",
		"site_security.verification_result_incomplete",
		"site_security.recheck_short",
	}
	for _, locale := range []string{DefaultLang, English} {
		for _, page := range []string{"websites_detail_content", "site_security_summary", "site_security_summary_script"} {
			t.Run(locale+"/"+page, func(t *testing.T) {
				var messages map[string]string
				if err := json.Unmarshal([]byte(catalog.JSON(locale, page)), &messages); err != nil {
					t.Fatal(err)
				}
				for _, key := range keys {
					want := T(locale, key)
					if want == key || want == "" || messages[key] != want {
						t.Errorf("page catalog is missing translated %s: got %q, want %q", key, messages[key], want)
					}
				}
			})
		}
	}
}
