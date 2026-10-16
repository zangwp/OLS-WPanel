package executor

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// validMemoryLimit accepts PHP memory limits such as 128M, 1G, 512K, or a byte count.
var validMemoryLimit = regexp.MustCompile(`^\d+[KMG]?$`)

var errWPConfigChanged = errors.New("wp-config.php changed after optimization update")

type WPOptimizations struct {
	DisableApplicationPasswords bool
	DisableUpdates              bool
	DisableFileEditing          bool
	WPDebug                     bool
	WPDebugDisplay              bool
	WPPostRevisions             int    // -1 removes the definition; >=0 defines the value.
	WPMemoryLimit               string // Empty removes the definition; otherwise e.g. "128M".
}

func ApplyWPOptimizations(webRoot string, opts WPOptimizations) error {
	_, _, err := updateWPConfig(webRoot, func(content string) string {
		return renderWPOptimizations(content, opts)
	})
	return err
}

func renderWPOptimizations(content string, opts WPOptimizations) string {

	// Insert enabled boolean constants; remove disabled ones.
	content = applyBoolConstant(content, "AUTOMATIC_UPDATER_DISABLED", opts.DisableUpdates)
	content = applyBoolConstant(content, "DISALLOW_FILE_EDIT", opts.DisableFileEditing)

	// WP_DEBUG manages all three debug constants; removing them restores the WordPress false default.
	content = applyBoolConstant(content, "WP_DEBUG", opts.WPDebug)
	if opts.WPDebug {
		content = applyBoolConstant(content, "WP_DEBUG_LOG", true)
		content = setBoolConstant(content, "WP_DEBUG_DISPLAY", opts.WPDebugDisplay)
	} else {
		content = removeConstant(content, "WP_DEBUG_LOG")
		content = removeConstant(content, "WP_DEBUG_DISPLAY")
	}

	if opts.WPPostRevisions >= 0 {
		content = applyIntConstant(content, "WP_POST_REVISIONS", opts.WPPostRevisions)
	} else {
		content = removeConstant(content, "WP_POST_REVISIONS")
	}

	// WP_MEMORY_LIMIT: empty removes it; reject invalid syntax that could corrupt the PHP file.
	if opts.WPMemoryLimit != "" {
		if validMemoryLimit.MatchString(strings.ToUpper(opts.WPMemoryLimit)) {
			content = applyStringConstant(content, "WP_MEMORY_LIMIT", strings.ToUpper(opts.WPMemoryLimit))
		}
	} else {
		content = removeConstant(content, "WP_MEMORY_LIMIT")
	}

	return renderWPNativePolicy(content, opts.DisableUpdates, opts.DisableApplicationPasswords)
}

// ApplyWPOptimizationsReversible applies the wp-config.php change and returns
// a function that restores the exact previous contents. The rollback refuses to
// overwrite a file changed by another actor after this update.
func ApplyWPOptimizationsReversible(webRoot string, opts WPOptimizations) (func() error, error) {
	before, after, err := updateWPConfig(webRoot, func(content string) string {
		return renderWPOptimizations(content, opts)
	})
	if err != nil {
		return nil, err
	}
	return func() error {
		configPath := filepath.Join(webRoot, "wp-config.php")
		current, err := os.ReadFile(configPath)
		if err != nil {
			return err
		}
		if !bytes.Equal(current, after) {
			return errWPConfigChanged
		}
		return writeWPConfig(configPath, before)
	}, nil
}

// SetWPFileEditingDisabled updates only the WordPress dashboard file editor
// setting without rewriting unrelated optimization constants.
func SetWPFileEditingDisabled(webRoot string, disabled bool) error {
	_, _, err := updateWPConfig(webRoot, func(content string) string {
		return applyBoolConstant(content, "DISALLOW_FILE_EDIT", disabled)
	})
	return err
}

// SetWPUpdatesDisabled updates only the WordPress automatic update setting
// without rewriting unrelated optimization constants.
func SetWPUpdatesDisabled(webRoot string, disabled bool) error {
	_, _, err := updateWPConfig(webRoot, func(content string) string {
		appDisabled := strings.Contains(content, "wp_is_application_passwords_available") && strings.Contains(content, "OLS-WPANEL-POLICY-BEGIN")
		return renderWPNativePolicy(applyBoolConstant(content, "AUTOMATIC_UPDATER_DISABLED", disabled), disabled, appDisabled)
	})
	return err
}

func updateWPConfig(webRoot string, transform func(string) string) ([]byte, []byte, error) {
	configPath := filepath.Join(webRoot, "wp-config.php")
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, nil, err
	}
	updated := []byte(transform(string(data)))
	if bytes.Equal(data, updated) {
		return data, updated, nil
	}
	if err := writeWPConfig(configPath, updated); err != nil {
		return nil, nil, err
	}
	return data, updated, nil
}

func writeWPConfig(configPath string, data []byte) error {
	info, err := os.Stat(configPath)
	if err != nil {
		return err
	}
	return os.WriteFile(configPath, data, info.Mode().Perm())
}

func constPattern(name string) *regexp.Regexp {
	return regexp.MustCompile(`(?m)^\s*define\s*\(\s*['"]` + regexp.QuoteMeta(name) + `['"]\s*,\s*[^)]+\)\s*;\s*\n?`)
}

func applyBoolConstant(content, name string, enable bool) string {
	re := constPattern(name)
	if enable {
		stmt := fmt.Sprintf("define('%s', true);\n", name)
		return insertBeforeMarker(re.ReplaceAllString(content, ""), stmt)
	}
	return re.ReplaceAllString(content, "")
}

func setBoolConstant(content, name string, value bool) string {
	re := constPattern(name)
	stmt := fmt.Sprintf("define('%s', %v);\n", name, value)
	return insertBeforeMarker(re.ReplaceAllString(content, ""), stmt)
}

func WPDebugDisplayEnabled(webRoot string) bool {
	data, err := os.ReadFile(filepath.Join(webRoot, "wp-config.php"))
	if err != nil {
		return false
	}
	return regexp.MustCompile(`(?im)^\s*define\s*\(\s*['"]WP_DEBUG_DISPLAY['"]\s*,\s*true\s*\)\s*;`).Match(data)
}

func applyIntConstant(content, name string, value int) string {
	re := constPattern(name)
	has := re.MatchString(content)
	stmt := fmt.Sprintf("define('%s', %d);\n", name, value)

	if has {
		return re.ReplaceAllString(content, stmt)
	}
	return insertBeforeMarker(content, stmt)
}

func applyStringConstant(content, name, value string) string {
	re := constPattern(name)
	has := re.MatchString(content)
	stmt := fmt.Sprintf("define('%s', '%s');\n", name, value)

	if has {
		return re.ReplaceAllString(content, stmt)
	}
	return insertBeforeMarker(content, stmt)
}

func removeConstant(content, name string) string {
	return constPattern(name).ReplaceAllString(content, "")
}

func insertBeforeMarker(content, insertion string) string {
	marker := "/* That's all, stop editing!"
	idx := strings.Index(content, marker)
	if idx < 0 {
		marker = "require_once ABSPATH . 'wp-settings.php';"
		idx = strings.Index(content, marker)
	}
	if idx >= 0 {
		return content[:idx] + insertion + content[idx:]
	}

	idx = strings.LastIndex(content, "?>")
	if idx > 0 {
		if idx > 0 && content[idx-1] != '\n' {
			insertion = "\n" + insertion
		}
		return content[:idx] + insertion + content[idx:]
	}

	phpOpen := "<?php"
	idx = strings.Index(content, phpOpen)
	if idx >= 0 {
		lineBreak := strings.IndexAny(content[idx+len(phpOpen):], "\r\n")
		if lineBreak >= 0 {
			insertPos := idx + len(phpOpen) + lineBreak + 1
			return content[:insertPos] + insertion + content[insertPos:]
		}
		return content[:idx+len(phpOpen)] + "\n" + insertion + "\n" + content[idx+len(phpOpen):]
	}

	return content + "\n" + insertion
}
