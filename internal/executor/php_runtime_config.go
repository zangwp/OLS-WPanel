package executor

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type PHPRuntimeConfig struct {
	MemoryLimit       string
	UploadMaxFilesize string
	PostMaxSize       string
	MaxExecutionTime  string
	MaxInputTime      string
	MaxInputVars      string
}

// Tests may override this path. Production derives it from the configured
// primary LSPHP branch so upgraded 8.3 installations are not silently pointed
// at the fresh-install 8.5 default.
var phpRuntimeConfigPath string

var phpRuntimeDefaults = PHPRuntimeConfig{
	MemoryLimit:       "256M",
	UploadMaxFilesize: "64M",
	PostMaxSize:       "64M",
	MaxExecutionTime:  "300",
	MaxInputTime:      "300",
	// The old 2000 limit silently truncated large WordPress admin forms such as
	// Elementor/ACF. Existing installs migrate in php_legacy_defaults_upgrade.go.
	MaxInputVars: "10000",
}

// phpOpcacheStaticDefaults contains hardware-independent OPcache and security
// defaults. Fill missing keys only; fixed order keeps output deterministic.
var phpOpcacheStaticDefaultKeys = []string{
	"expose_php",
	"opcache.enable",
	"opcache.interned_strings_buffer",
	"opcache.validate_timestamps",
	"opcache.revalidate_freq",
	"opcache.save_comments",
}

var phpOpcacheStaticDefaults = map[string]string{
	"expose_php":                      "Off",
	"opcache.enable":                  "1",
	"opcache.interned_strings_buffer": "8",
	"opcache.validate_timestamps":     "1",
	"opcache.revalidate_freq":         "5",
	"opcache.save_comments":           "1",
}

func PHPRuntimeConfigPath() string {
	if path := strings.TrimSpace(phpRuntimeConfigPath); path != "" {
		return path
	}
	version := PrimaryLSPHPVersion()
	suffix := strings.ReplaceAll(version, ".", "")
	return filepath.Join("/usr/local/lsws", "lsphp"+suffix, "etc", "php", version, "mods-available", "99-ols-wpanel.ini")
}

func EnsurePHPRuntimeConfigFile() (bool, error) {
	path := PHPRuntimeConfigPath()
	migrated := false
	if strings.TrimSpace(phpRuntimeConfigPath) == "" {
		var err error
		migrated, err = migratePHPRuntimeConfig(legacyLSPHPRuntimeConfigPath(PrimaryLSPHPVersion()), path)
		if err != nil {
			return false, err
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return false, err
	}
	data, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return false, err
	}

	if os.IsNotExist(err) {
		return true, os.WriteFile(path, []byte(defaultPHPRuntimeConfigContent()), 0644)
	}

	content := string(data)
	next := ensureIniValue(content, "memory_limit", phpRuntimeDefaults.MemoryLimit)
	next = ensureIniValue(next, "upload_max_filesize", phpRuntimeDefaults.UploadMaxFilesize)
	next = ensureIniValue(next, "post_max_size", phpRuntimeDefaults.PostMaxSize)
	next = ensureIniValue(next, "max_execution_time", phpRuntimeDefaults.MaxExecutionTime)
	next = ensureIniValue(next, "max_input_time", phpRuntimeDefaults.MaxInputTime)
	next = ensureIniValue(next, "max_input_vars", phpRuntimeDefaults.MaxInputVars)
	for _, key := range phpOpcacheStaticDefaultKeys {
		next = ensureIniValue(next, key, phpOpcacheStaticDefaults[key])
	}

	// Set hardware-based initial OPcache memory and file-count recommendations
	// only for missing keys; preserve all existing values.
	memMB, maxFiles := recommendedOpcacheAdaptiveDefaults()
	next = ensureIniValue(next, "opcache.memory_consumption", memMB)
	next = ensureIniValue(next, "opcache.max_accelerated_files", maxFiles)

	if next == content {
		return migrated, nil
	}
	return true, os.WriteFile(path, []byte(next), 0644)
}

func legacyLSPHPRuntimeConfigPath(version string) string {
	suffix := strings.ReplaceAll(version, ".", "")
	return filepath.Join("/usr/local/lsws", "lsphp"+suffix, "etc", "php", version, "litespeed", "conf.d", "99-ols-wpanel.ini")
}

// Preserve the old file for rollback and never replace a configuration that
// already exists in the vendor's actual scan directory.
func migratePHPRuntimeConfig(legacyPath, path string) (bool, error) {
	if _, err := os.Lstat(path); err == nil {
		return false, nil
	} else if !os.IsNotExist(err) {
		return false, err
	}
	info, err := os.Lstat(legacyPath)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || info.Size() > lsphpHealthOutputLimit {
		return false, fmt.Errorf("legacy PHP runtime configuration is not a safe regular file")
	}
	productionPath := strings.HasPrefix(filepath.ToSlash(legacyPath), "/usr/local/lsws/")
	scope, _, _ := strings.Cut(filepath.ToSlash(legacyPath), "/etc/php/")
	if productionPath && !lsphpHealthTrustedPath(legacyPath, filepath.FromSlash(scope), "file", fileOwnerIDs) {
		return false, fmt.Errorf("legacy PHP runtime configuration is not trusted")
	}
	data, err := os.ReadFile(legacyPath)
	if err != nil {
		return false, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return false, err
	}
	if productionPath && !lsphpHealthTrustedPath(filepath.Dir(path), filepath.FromSlash(scope), "directory", fileOwnerIDs) {
		return false, fmt.Errorf("PHP runtime configuration directory is not trusted")
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if os.IsExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	_, writeErr := file.Write(data)
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		_ = os.Remove(path)
		if writeErr != nil {
			return false, writeErr
		}
		return false, closeErr
	}
	return true, nil
}

// recommendedOpcacheAdaptiveDefaults recommends initial OPcache memory in MB
// and file count for missing keys in generated runtime configurations.
func recommendedOpcacheAdaptiveDefaults() (memoryConsumptionMB string, maxAcceleratedFiles string) {
	facts := CollectSystemFacts()
	return strconv.Itoa(RecommendOPcacheMemoryConsumptionMB(facts)),
		strconv.Itoa(RecommendOPcacheMaxAcceleratedFiles(facts))
}

func LoadPHPRuntimeConfig() PHPRuntimeConfig {
	cfg := phpRuntimeDefaults
	data, err := os.ReadFile(PHPRuntimeConfigPath())
	if err != nil {
		return cfg
	}
	content := string(data)
	if v := findIniValue(content, "memory_limit"); v != "" {
		cfg.MemoryLimit = v
	}
	if v := findIniValue(content, "upload_max_filesize"); v != "" {
		cfg.UploadMaxFilesize = v
	}
	if v := findIniValue(content, "post_max_size"); v != "" {
		cfg.PostMaxSize = v
	}
	if v := findIniValue(content, "max_execution_time"); v != "" {
		cfg.MaxExecutionTime = v
	}
	if v := findIniValue(content, "max_input_time"); v != "" {
		cfg.MaxInputTime = v
	}
	if v := findIniValue(content, "max_input_vars"); v != "" {
		cfg.MaxInputVars = v
	}
	return cfg
}

func defaultPHPRuntimeConfigContent() string {
	memMB, maxFiles := recommendedOpcacheAdaptiveDefaults()
	return `; OLS WPanel - WordPress runtime baseline
; These values are managed by Software Management.
memory_limit = ` + phpRuntimeDefaults.MemoryLimit + `
upload_max_filesize = ` + phpRuntimeDefaults.UploadMaxFilesize + `
post_max_size = ` + phpRuntimeDefaults.PostMaxSize + `
max_execution_time = ` + phpRuntimeDefaults.MaxExecutionTime + `
max_input_time = ` + phpRuntimeDefaults.MaxInputTime + `
max_input_vars = ` + phpRuntimeDefaults.MaxInputVars + `
expose_php = ` + phpOpcacheStaticDefaults["expose_php"] + `
opcache.enable = ` + phpOpcacheStaticDefaults["opcache.enable"] + `
opcache.interned_strings_buffer = ` + phpOpcacheStaticDefaults["opcache.interned_strings_buffer"] + `
opcache.memory_consumption = ` + memMB + `
opcache.max_accelerated_files = ` + maxFiles + `
opcache.validate_timestamps = ` + phpOpcacheStaticDefaults["opcache.validate_timestamps"] + `
opcache.revalidate_freq = ` + phpOpcacheStaticDefaults["opcache.revalidate_freq"] + `
opcache.save_comments = ` + phpOpcacheStaticDefaults["opcache.save_comments"] + `
`
}

func ensureIniValue(content, key, value string) string {
	if findIniValue(content, key) != "" {
		return content
	}
	return strings.TrimRight(content, "\n") + "\n" + key + " = " + value + "\n"
}

// setIniValue replaces an existing key's value and leaves content unchanged
// when the key is missing; callers must handle adding missing keys.
func setIniValue(content, key, value string) string {
	lines := strings.Split(content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, ";") || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.HasPrefix(trimmed, key+" =") || strings.HasPrefix(trimmed, key+"=") {
			lines[i] = key + " = " + value
			return strings.Join(lines, "\n")
		}
	}
	return content
}

func findIniValue(content, key string) string {
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, ";") || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.HasPrefix(trimmed, key+" =") || strings.HasPrefix(trimmed, key+"=") {
			parts := strings.SplitN(trimmed, "=", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1])
			}
		}
	}
	return ""
}
