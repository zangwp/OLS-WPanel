package tests

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"unicode"
)

const (
	zhLocalePath = "../internal/i18n/locales/zh-CN.json"
	enLocalePath = "../internal/i18n/locales/en-US.json"
)

func TestLocalesHaveMatchingKeys(t *testing.T) {
	zh, en := loadLocales(t)
	assertSameKeys(t, flattenedKeys(zh), flattenedKeys(en))
}

func TestEnglishLocaleContainsNoUnexpectedChinese(t *testing.T) {
	_, en := loadLocales(t)
	hanPattern := regexp.MustCompile(`\p{Han}`)
	for _, key := range flattenedKeys(en) {
		value, ok := lookup(en, key).(string)
		if ok && hanPattern.MatchString(value) {
			t.Errorf("en-US translation %q contains Chinese text: %q", key, value)
		}
	}
}

func TestReferencedTranslationKeysExist(t *testing.T) {
	zh, en := loadLocales(t)
	references := collectTranslationReferences(t, appendUnique(flattenedKeys(zh), flattenedKeys(en)...))
	for source, keys := range references {
		for _, key := range keys {
			if lookup(zh, key) == nil {
				t.Errorf("%s uses key %q missing from zh-CN", source, key)
			}
			if lookup(en, key) == nil {
				t.Errorf("%s uses key %q missing from en-US", source, key)
			}
		}
	}
}

func TestTemplateScriptKeysAreExposed(t *testing.T) {
	zh, en := loadLocales(t)
	scriptKeys := collectScriptTranslationKeys(t, appendUnique(flattenedKeys(zh), flattenedKeys(en)...))
	if len(scriptKeys) == 0 {
		return
	}

	exposed := collectExposedKeys(t)
	for source, keys := range scriptKeys {
		for _, key := range keys {
			if !exposed[key] {
				t.Errorf("%s uses unexposed JavaScript translation key %q", source, key)
			}
		}
	}
}

func loadLocales(t *testing.T) (map[string]any, map[string]any) {
	t.Helper()
	zh, zhErr := readLocale(zhLocalePath)
	en, enErr := readLocale(enLocalePath)
	if errors.Is(zhErr, fs.ErrNotExist) && errors.Is(enErr, fs.ErrNotExist) {
		t.Skip("i18n locales do not exist yet; guards activate when both locale files are added")
	}
	if zhErr != nil {
		t.Fatalf("read %s: %v", zhLocalePath, zhErr)
	}
	if enErr != nil {
		t.Fatalf("read %s: %v", enLocalePath, enErr)
	}
	return zh, en
}

func readLocale(path string) (map[string]any, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var locale map[string]any
	if err := json.Unmarshal(data, &locale); err != nil {
		return nil, err
	}
	return locale, nil
}

func assertSameKeys(t *testing.T, zhKeys, enKeys []string) {
	t.Helper()
	zh := make(map[string]bool, len(zhKeys))
	en := make(map[string]bool, len(enKeys))
	for _, key := range zhKeys {
		zh[key] = true
	}
	for _, key := range enKeys {
		en[key] = true
	}
	for _, key := range zhKeys {
		if !en[key] {
			t.Errorf("en-US locale is missing key %q", key)
		}
	}
	for _, key := range enKeys {
		if !zh[key] {
			t.Errorf("zh-CN locale is missing key %q", key)
		}
	}
}

func flattenedKeys(messages map[string]any) []string {
	var keys []string
	var walk func(map[string]any, string)
	walk = func(current map[string]any, prefix string) {
		for key, value := range current {
			fullKey := key
			if prefix != "" {
				fullKey = prefix + "." + key
			}
			if nested, ok := value.(map[string]any); ok {
				walk(nested, fullKey)
				continue
			}
			keys = append(keys, fullKey)
		}
	}
	walk(messages, "")
	sort.Strings(keys)
	return keys
}

func lookup(messages map[string]any, key string) any {
	var current any = messages
	for _, part := range strings.Split(key, ".") {
		nested, ok := current.(map[string]any)
		if !ok {
			return nil
		}
		current = nested[part]
		if current == nil {
			return nil
		}
	}
	return current
}

func collectTranslationReferences(t *testing.T, knownKeys []string) map[string][]string {
	t.Helper()
	references := map[string][]string{}
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`i18n\.(?:TE|T)\([^,\n]+,\s*"([^"]+)"`),
		regexp.MustCompile(`\{\{t \.Lang "([^"]+)"`),
	}
	walkFiles(t, "..", func(path string, content []byte) {
		if strings.HasSuffix(path, "_test.go") {
			return
		}
		for _, pattern := range patterns {
			keys, err := translationKeysFromContent(content, pattern, knownKeys)
			if err != nil {
				t.Errorf("%s: %v", path, err)
			}
			references[path] = appendUnique(references[path], keys...)
		}
	})
	for source, keys := range collectScriptTranslationKeys(t, knownKeys) {
		references[source] = appendUnique(references[source], keys...)
	}
	return references
}

var scriptTranslationKeyPattern = regexp.MustCompile(`(?:^|[^A-Za-z0-9_$])t\('([a-z][a-z0-9_.-]+)'`)

// Only an explicit concatenation after the quoted literal creates a prefix.
// A static unknown key, including one ending in an underscore or dot, must
// remain a reference so the existence and exposure guards reject it.
func translationKeysFromContent(content []byte, pattern *regexp.Regexp, knownKeys []string) ([]string, error) {
	var keys []string
	for _, match := range pattern.FindAllSubmatchIndex(content, -1) {
		literal := string(content[match[2]:match[3]])
		tail := strings.TrimLeftFunc(string(content[match[1]:]), unicode.IsSpace)
		if !strings.HasPrefix(tail, "+") {
			keys = appendUnique(keys, literal)
			continue
		}
		var expanded []string
		for _, key := range knownKeys {
			if len(key) > len(literal) && strings.HasPrefix(key, literal) {
				expanded = appendUnique(expanded, key)
			}
		}
		if len(expanded) == 0 {
			return nil, fmt.Errorf("dynamic translation prefix %q has no locale keys", literal)
		}
		keys = appendUnique(keys, expanded...)
	}
	return keys, nil
}

func TestTranslationReferencesExpandOnlyExplicitDynamicPrefixes(t *testing.T) {
	known := []string{"common.confirm", "site_security.reason_first", "site_security.reason_second"}
	goPattern := regexp.MustCompile(`i18n\.(?:TE|T)\([^,\n]+,\s*"([^"]+)"`)
	for _, tc := range []struct {
		name, source string
		pattern      *regexp.Regexp
		want         []string
		wantError    bool
	}{
		{"JavaScript prefix expands every variant", `t('site_security.reason_' + check.message_code)`, scriptTranslationKeyPattern, []string{"site_security.reason_first", "site_security.reason_second"}, false},
		{"multiline concatenation", "t('site_security.reason_'\n  + code)", scriptTranslationKeyPattern, []string{"site_security.reason_first", "site_security.reason_second"}, false},
		{"Go prefix expands every variant", `i18n.T(lang, "site_security.reason_"+code)`, goPattern, []string{"site_security.reason_first", "site_security.reason_second"}, false},
		{"ordinary literal remains exact", `t('common.confirm')`, scriptTranslationKeyPattern, []string{"common.confirm"}, false},
		{"static unknown underscore remains invalid reference", `t('common.unknown_')`, scriptTranslationKeyPattern, []string{"common.unknown_"}, false},
		{"static unknown dot remains invalid reference", `i18n.T(lang, "common.unknown.")`, goPattern, []string{"common.unknown."}, false},
		{"concatenation outside call remains static", `t('common.unknown_') + suffix`, scriptTranslationKeyPattern, []string{"common.unknown_"}, false},
		{"unknown JavaScript dynamic prefix rejected", `t('common.unknown_' + code)`, scriptTranslationKeyPattern, nil, true},
		{"unknown Go dynamic prefix rejected", `i18n.T(lang, "common.unknown_"+code)`, goPattern, nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := translationKeysFromContent([]byte(tc.source), tc.pattern, known)
			if (err != nil) != tc.wantError {
				t.Fatalf("reference parse error=%v, expected error=%t", err, tc.wantError)
			}
			if strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Fatalf("reference keys=%v, expected %v", got, tc.want)
			}
		})
	}
	// Every expanded variant reaches the exposure guard. Exposing only the first
	// dynamic result must not hide another result from the same locale prefix.
	keys, err := translationKeysFromContent([]byte(`t('site_security.reason_' + code)`), scriptTranslationKeyPattern, known)
	if err != nil {
		t.Fatal(err)
	}
	exposed := map[string]bool{"site_security.reason_first": true}
	var missing []string
	for _, key := range keys {
		if !exposed[key] {
			missing = append(missing, key)
		}
	}
	if strings.Join(missing, ",") != "site_security.reason_second" {
		t.Fatalf("unexposed dynamic references=%v, expected the second variant", missing)
	}
}

func collectScriptTranslationKeys(t *testing.T, knownKeys []string) map[string][]string {
	t.Helper()
	keys := map[string][]string{}
	collect := func(path string, content []byte) {
		found, err := translationKeysFromContent(content, scriptTranslationKeyPattern, knownKeys)
		if err != nil {
			t.Errorf("%s: %v", path, err)
		}
		keys[path] = appendUnique(keys[path], found...)
	}

	walkFiles(t, "../web/templates", func(path string, content []byte) {
		collect(path, content)
	})
	content, err := os.ReadFile("../web/js/app.js")
	if err == nil {
		collect("../web/js/app.js", content)
	} else if !errors.Is(err, fs.ErrNotExist) {
		t.Fatal(err)
	}
	return keys
}

func collectExposedKeys(t *testing.T) map[string]bool {
	t.Helper()
	content, err := os.ReadFile("../internal/router/router.go")
	if err != nil {
		t.Fatal(err)
	}
	blockPattern := regexp.MustCompile(`(?s)var\s+i18nKeys\s*=\s*\[\]string\s*\{(.*?)\}`)
	match := blockPattern.FindSubmatch(content)
	if match == nil {
		t.Fatal("router/router.go must define i18nKeys when JavaScript translation keys are used")
	}
	keyPattern := regexp.MustCompile(`"([a-z][a-z0-9_.-]+)"`)
	exposed := map[string]bool{}
	for _, keyMatch := range keyPattern.FindAllSubmatch(match[1], -1) {
		exposed[string(keyMatch[1])] = true
	}
	return exposed
}

func walkFiles(t *testing.T, root string, visit func(string, []byte)) {
	t.Helper()
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			switch entry.Name() {
			case ".git", ".cache", ".gocache", ".codex-deploy", ".playwright-cli", "dist", "output":
				return filepath.SkipDir
			}
			return nil
		}
		switch filepath.Ext(path) {
		case ".go", ".html", ".js":
			content, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			visit(path, content)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func appendUnique(values []string, additions ...string) []string {
	seen := make(map[string]bool, len(values)+len(additions))
	for _, value := range values {
		seen[value] = true
	}
	for _, value := range additions {
		if !seen[value] {
			values = append(values, value)
			seen[value] = true
		}
	}
	sort.Strings(values)
	return values
}
