package tests

import (
	"html/template"
	"os"
	"strings"
	"testing"
)

func TestSoftwarePageKeepsOperationalStatusCompact(t *testing.T) {
	source, err := os.ReadFile("../web/templates/software.html")
	if err != nil {
		t.Fatal(err)
	}
	page := string(source)
	if _, err := template.New("software").Funcs(template.FuncMap{
		"t": func(_ string, _ string) string { return "" },
	}).Parse(page); err != nil {
		t.Fatalf("parse software template: %v", err)
	}

	for _, required := range []string{
		"software-tabs",
		"software.tab_runtime",
		"software.tab_tuning",
		"software.development_tools",
		"software.primary_runtime",
		"configurableSoftware()",
		"x-model=\"cfg._value\"",
		"software.recommend_basis",
		"cfg._recommended = recs[cfg.key]",
		"software.confirm_stop_service",
		"software.confirm_restart_service",
	} {
		if !strings.Contains(page, required) {
			t.Errorf("software page is missing %q", required)
		}
	}

	for _, removed := range []string{
		"software.tab_tools",
		"software.suggested_value",
		"this.recommend(sw, true)",
		"cfg._value = recs[cfg.key]",
		"software.repository_current",
		"software.process_guard\"}}</h3>",
	} {
		if strings.Contains(page, removed) {
			t.Errorf("software page still contains obsolete UI %q", removed)
		}
	}
}
