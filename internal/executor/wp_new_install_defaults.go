package executor

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

//go:embed assets/wp-new-install-defaults.php
var newWordPressDefaultsSource string

const newWordPressDefaultsHelper = "ols-wpanel-new-install-defaults.php"

type newWordPressDefaultsManifest struct {
	OfficialPackage bool                         `json:"official_package"`
	Plugins         map[string]map[string]string `json:"plugins"`
	Themes          map[string]map[string]string `json:"themes"`
	Errors          []string                     `json:"errors"`
}

// Exact core theme slugs, never a twenty* pattern. Unknown future themes stay
// in place until reviewed. This list follows WordPress WP_Theme::$default_themes.
var wordPressBundledThemeSlugs = []string{
	"classic", "default", "twentyten", "twentyeleven", "twentytwelve", "twentythirteen",
	"twentyfourteen", "twentyfifteen", "twentysixteen", "twentyseventeen", "twentynineteen",
	"twentytwenty", "twentytwentyone", "twentytwentytwo", "twentytwentythree", "twentytwentyfour", "twentytwentyfive",
}

// Called only while executeCreateSite owns a freshly deployed, unpublished
// site directory. Generic deployment, reinstall, restore and import do not
// install this one-shot helper. The initial WordPress wizard installs its DB
// later, so theme pruning must wait for WordPress's wp_install hook.
func prepareNewWordPressDefaults(webRoot string, officialPackage bool) error {
	manifest := newWordPressDefaultsManifest{OfficialPackage: officialPackage, Plugins: map[string]map[string]string{}, Themes: map[string]map[string]string{}, Errors: []string{}}
	capture := func(kind, slug string, target map[string]map[string]string) {
		path, err := managedWordPressPath(webRoot, "wp-content", kind, slug)
		if err != nil {
			manifest.Errors = append(manifest.Errors, kind+"/"+slug+": unsafe path")
			return
		}
		files, err := fingerprintNewWordPressDefault(path)
		if os.IsNotExist(err) {
			return
		}
		if err != nil {
			manifest.Errors = append(manifest.Errors, kind+"/"+slug+": unreadable or unsafe package files")
			return
		}
		target[slug] = files
	}
	if officialPackage {
		for _, slug := range []string{"akismet", "hello.php"} {
			capture("plugins", slug, manifest.Plugins)
		}
		for _, slug := range wordPressBundledThemeSlugs {
			capture("themes", slug, manifest.Themes)
		}
	} else {
		manifest.Errors = append(manifest.Errors, "Official download provenance unavailable; uploaded or unverified package contents were preserved.")
	}
	encoded, err := json.Marshal(manifest)
	if err != nil {
		return err
	}
	content := strings.Replace(newWordPressDefaultsSource, "__OLS_WPANEL_DEFAULTS_MANIFEST__", phpSingleQuoteEscape(string(encoded)), 1)
	path, err := managedWordPressPath(webRoot, "wp-content", "mu-plugins", newWordPressDefaultsHelper)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		return fmt.Errorf("准备新安装 WordPress 默认内容清理失败: %w", err)
	}
	_, writeErr := io.WriteString(file, content)
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		_ = os.Remove(path)
		return fmt.Errorf("写入新安装 WordPress 默认内容清理失败: %v; %v", writeErr, closeErr)
	}
	return nil
}

// Fingerprint the complete original tree. A user-modified default theme or
// plugin is preserved, including additional files/directories and symlinks.
func fingerprintNewWordPressDefault(root string) (map[string]string, error) {
	files := map[string]string{}
	var totalBytes int64
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.Type()&os.ModeSymlink != 0 || (!entry.IsDir() && !entry.Type().IsRegular()) {
			return fmt.Errorf("默认内容包含非普通文件")
		}
		if len(files) >= 10000 {
			return fmt.Errorf("默认内容文件数量过多")
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if rel != "." {
				files[filepath.ToSlash(rel)+"/"] = ""
			}
			return nil
		}
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		hash := sha256.New()
		size, readErr := io.Copy(hash, io.LimitReader(file, 64*1024*1024-totalBytes+1))
		closeErr := file.Close()
		totalBytes += size
		if readErr != nil || closeErr != nil || totalBytes > 64*1024*1024 {
			return fmt.Errorf("默认内容不可读取或过大")
		}
		files[filepath.ToSlash(rel)] = hex.EncodeToString(hash.Sum(nil))
		return nil
	})
	return files, err
}
