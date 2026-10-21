package executor

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	liteSpeedCachePinnedVersion = "7.9.2"
	// Checked against all 320 official per-file SHA-256 values before pinning.
	liteSpeedCachePinnedSHA256 = "b2fceff4b335a51bf27a974faea74233467d66ea1eb180b8b21eeead8bb4f40c"
	liteSpeedCacheMetadataURL  = "https://api.wordpress.org/plugins/info/1.2/?action=plugin_information&request%5Bfields%5D%5Bsections%5D=0&request%5Bslug%5D=litespeed-cache"
	liteSpeedCacheMaxZIPBytes  = 8 << 20
	liteSpeedCacheMaxJSONBytes = 1 << 20
	liteSpeedCacheMaxFiles     = 5_000
	liteSpeedCacheMaxFileBytes = 16 << 20
	liteSpeedCacheMaxTotal     = 64 << 20
)

var liteSpeedCacheVersionPattern = regexp.MustCompile(`^(0|[1-9][0-9]{0,8})(\.(0|[1-9][0-9]{0,8})){0,3}$`)

type liteSpeedCachePackage struct {
	Path, Version, SHA256 string
	Fallback              bool
}

type liteSpeedCachePackageService struct {
	client       *http.Client
	tempDir      string
	pinnedSHA256 string
}

type liteSpeedCachePluginInfo struct {
	Slug            string   `json:"slug"`
	Version         string   `json:"version"`
	DownloadLink    string   `json:"download_link"`
	Requires        string   `json:"requires"`
	RequiresPHP     string   `json:"requires_php"`
	RequiresPlugins []string `json:"requires_plugins"`
}

type liteSpeedCacheChecksums struct {
	Plugin  string `json:"plugin"`
	Version string `json:"version"`
	Files   map[string]struct {
		SHA256 string `json:"sha256"`
	} `json:"files"`
}

func acquireLiteSpeedCachePackage(ctx context.Context, wpVersion, phpVersion string) (liteSpeedCachePackage, error) {
	service := newLiteSpeedCachePackageService(nil)
	return service.acquire(ctx, wpVersion, phpVersion)
}

func newLiteSpeedCachePackageService(client *http.Client) *liteSpeedCachePackageService {
	if client == nil {
		client = &http.Client{Timeout: 40 * time.Second}
	}
	// Copy the client so callers cannot accidentally replace the redirect policy.
	strictClient := *client
	strictClient.CheckRedirect = func(*http.Request, []*http.Request) error {
		return fmt.Errorf("LiteSpeed Cache download redirects are not allowed")
	}
	if strictClient.Timeout <= 0 || strictClient.Timeout > 40*time.Second {
		strictClient.Timeout = 40 * time.Second
	}
	return &liteSpeedCachePackageService{client: &strictClient, pinnedSHA256: liteSpeedCachePinnedSHA256}
}

func (s *liteSpeedCachePackageService) acquire(ctx context.Context, wpVersion, phpVersion string) (liteSpeedCachePackage, error) {
	if err := ctx.Err(); err != nil {
		return liteSpeedCachePackage{}, err
	}
	if !liteSpeedCacheVersionPattern.MatchString(wpVersion) || !liteSpeedCacheVersionPattern.MatchString(phpVersion) {
		return liteSpeedCachePackage{}, fmt.Errorf("无法确认 LiteSpeed Cache 所需的 WordPress 或 PHP 版本")
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	pkg, latestErr := s.acquireLatest(ctx, wpVersion, phpVersion)
	if latestErr == nil {
		return pkg, nil
	}
	if err := ctx.Err(); err != nil {
		return liteSpeedCachePackage{}, err
	}
	pkg, pinnedErr := s.acquirePinned(ctx, wpVersion, phpVersion)
	if pinnedErr != nil {
		if err := ctx.Err(); err != nil {
			return liteSpeedCachePackage{}, err
		}
		return liteSpeedCachePackage{}, fmt.Errorf("获取兼容的 LiteSpeed Cache 稳定版失败: %v；已校验的备用版本 %s 也不可用: %w", latestErr, liteSpeedCachePinnedVersion, pinnedErr)
	}
	return pkg, nil
}

func (s *liteSpeedCachePackageService) acquireLatest(ctx context.Context, wpVersion, phpVersion string) (liteSpeedCachePackage, error) {
	var metadata liteSpeedCachePluginInfo
	if err := s.getJSON(ctx, liteSpeedCacheMetadataURL, &metadata); err != nil {
		return liteSpeedCachePackage{}, fmt.Errorf("读取官方插件版本失败: %w", err)
	}
	if metadata.Slug != "litespeed-cache" || !liteSpeedCacheVersionPattern.MatchString(metadata.Version) ||
		compareLiteSpeedCacheVersions(metadata.Version, liteSpeedCachePinnedVersion) < 0 ||
		metadata.DownloadLink != liteSpeedCacheZIPURL(metadata.Version) || len(metadata.RequiresPlugins) != 0 {
		return liteSpeedCachePackage{}, fmt.Errorf("官方 LiteSpeed Cache 版本信息无效")
	}
	if err := checkLiteSpeedCacheRequirements(wpVersion, phpVersion, metadata.Requires, metadata.RequiresPHP); err != nil {
		return liteSpeedCachePackage{}, err
	}
	var checksums liteSpeedCacheChecksums
	if err := s.getJSON(ctx, liteSpeedCacheChecksumsURL(metadata.Version), &checksums); err != nil {
		return liteSpeedCachePackage{}, fmt.Errorf("读取 LiteSpeed Cache 官方 SHA-256 清单失败: %w", err)
	}
	if err := validateLiteSpeedCacheChecksums(checksums, metadata.Version); err != nil {
		return liteSpeedCachePackage{}, err
	}
	filename, err := s.download(ctx, liteSpeedCacheZIPURL(metadata.Version))
	if err != nil {
		return liteSpeedCachePackage{}, err
	}
	keep := false
	defer func() {
		if !keep {
			_ = os.Remove(filename)
		}
	}()
	digest, err := validateLiteSpeedCachePackage(ctx, filename, metadata.Version, wpVersion, phpVersion, &checksums)
	if err != nil {
		return liteSpeedCachePackage{}, err
	}
	keep = true
	return liteSpeedCachePackage{Path: filename, Version: metadata.Version, SHA256: digest}, nil
}

func (s *liteSpeedCachePackageService) acquirePinned(ctx context.Context, wpVersion, phpVersion string) (liteSpeedCachePackage, error) {
	// The pinned package's requirements remain available when the API is down.
	if err := checkLiteSpeedCacheRequirements(wpVersion, phpVersion, "6.0", "7.4"); err != nil {
		return liteSpeedCachePackage{}, err
	}
	filename, err := s.download(ctx, liteSpeedCacheZIPURL(liteSpeedCachePinnedVersion))
	if err != nil {
		return liteSpeedCachePackage{}, err
	}
	keep := false
	defer func() {
		if !keep {
			_ = os.Remove(filename)
		}
	}()
	digest, err := validateLiteSpeedCachePackage(ctx, filename, liteSpeedCachePinnedVersion, wpVersion, phpVersion, nil)
	if err != nil {
		return liteSpeedCachePackage{}, err
	}
	if !validLiteSpeedCacheSHA256(s.pinnedSHA256) || digest != s.pinnedSHA256 {
		return liteSpeedCachePackage{}, fmt.Errorf("LiteSpeed Cache 备用插件包 SHA-256 校验失败")
	}
	keep = true
	return liteSpeedCachePackage{Path: filename, Version: liteSpeedCachePinnedVersion, SHA256: digest, Fallback: true}, nil
}

func liteSpeedCacheZIPURL(version string) string {
	return "https://downloads.wordpress.org/plugin/litespeed-cache." + version + ".zip"
}

func liteSpeedCacheChecksumsURL(version string) string {
	return "https://downloads.wordpress.org/plugin-checksums/litespeed-cache/" + version + ".json"
}

func validLiteSpeedCacheSource(raw string) bool {
	if raw == liteSpeedCacheMetadataURL {
		return true
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host != "downloads.wordpress.org" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.RawPath != "" {
		return false
	}
	for _, prefix := range []string{"/plugin/litespeed-cache.", "/plugin-checksums/litespeed-cache/"} {
		suffix := ".zip"
		if strings.Contains(prefix, "checksums") {
			suffix = ".json"
		}
		if strings.HasPrefix(u.Path, prefix) && strings.HasSuffix(u.Path, suffix) {
			version := strings.TrimSuffix(strings.TrimPrefix(u.Path, prefix), suffix)
			return liteSpeedCacheVersionPattern.MatchString(version)
		}
	}
	return false
}

func (s *liteSpeedCachePackageService) request(ctx context.Context, source string) (*http.Response, error) {
	if !validLiteSpeedCacheSource(source) {
		return nil, fmt.Errorf("LiteSpeed Cache 下载地址无效")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, source, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "OLS-WPanel-LiteSpeed-Cache")
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.Request == nil || resp.Request.URL == nil || resp.Request.URL.String() != source || resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		return nil, fmt.Errorf("LiteSpeed Cache 官方源返回异常状态或地址")
	}
	return resp, nil
}

func (s *liteSpeedCachePackageService) getJSON(ctx context.Context, source string, dest any) error {
	resp, err := s.request(ctx, source)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(liteSpeedCacheContextReader{ctx, resp.Body}, liteSpeedCacheMaxJSONBytes+1))
	if err != nil {
		return err
	}
	if len(body) == 0 || len(body) > liteSpeedCacheMaxJSONBytes {
		return fmt.Errorf("LiteSpeed Cache 官方 JSON 数据大小异常")
	}
	if err := json.Unmarshal(body, dest); err != nil {
		return fmt.Errorf("LiteSpeed Cache 官方 JSON 数据无效: %w", err)
	}
	return nil
}

func (s *liteSpeedCachePackageService) download(ctx context.Context, source string) (string, error) {
	resp, err := s.request(ctx, source)
	if err != nil {
		return "", fmt.Errorf("下载 LiteSpeed Cache 插件失败: %w", err)
	}
	defer resp.Body.Close()
	if resp.ContentLength > liteSpeedCacheMaxZIPBytes {
		return "", fmt.Errorf("LiteSpeed Cache 插件包大小异常")
	}
	f, err := os.CreateTemp(s.tempDir, "ols-wpanel-litespeed-cache-*.zip")
	if err != nil {
		return "", fmt.Errorf("创建 LiteSpeed Cache 插件临时文件失败: %w", err)
	}
	filename := f.Name()
	n, copyErr := io.Copy(f, io.LimitReader(liteSpeedCacheContextReader{ctx, resp.Body}, liteSpeedCacheMaxZIPBytes+1))
	closeErr := f.Close()
	if copyErr != nil || closeErr != nil || n <= 0 || n > liteSpeedCacheMaxZIPBytes {
		_ = os.Remove(filename)
		if copyErr != nil {
			return "", copyErr
		}
		if closeErr != nil {
			return "", closeErr
		}
		return "", fmt.Errorf("LiteSpeed Cache 插件包大小异常")
	}
	return filename, nil
}

type liteSpeedCacheContextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r liteSpeedCacheContextReader) Read(body []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(body)
}

func validateLiteSpeedCacheChecksums(checksums liteSpeedCacheChecksums, version string) error {
	if checksums.Plugin != "litespeed-cache" || checksums.Version != version || len(checksums.Files) == 0 || len(checksums.Files) > liteSpeedCacheMaxFiles {
		return fmt.Errorf("LiteSpeed Cache 官方 SHA-256 清单身份无效")
	}
	for name, digest := range checksums.Files {
		if name == "." || name == ".." || path.Clean(name) != name || strings.HasPrefix(name, "/") || strings.HasPrefix(name, "../") ||
			strings.ContainsAny(name, "\\\x00:") || len(name) > wpComponentMaxPathBytes || !validLiteSpeedCacheSHA256(digest.SHA256) {
			return fmt.Errorf("LiteSpeed Cache 官方 SHA-256 清单条目无效")
		}
	}
	return nil
}

func validLiteSpeedCacheSHA256(value string) bool {
	if len(value) != 64 || value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func validateLiteSpeedCachePackage(ctx context.Context, filename, version, wpVersion, phpVersion string, checksums *liteSpeedCacheChecksums) (string, error) {
	if !liteSpeedCacheVersionPattern.MatchString(version) {
		return "", fmt.Errorf("LiteSpeed Cache 插件版本无效")
	}
	if checksums != nil {
		if err := validateLiteSpeedCacheChecksums(*checksums, version); err != nil {
			return "", err
		}
	}
	policy := WordPressFullZIPPolicy()
	policy.MaxArchiveBytes = liteSpeedCacheMaxZIPBytes
	policy.MaxEntries = liteSpeedCacheMaxFiles * 2
	policy.MaxEntryUncompressed = liteSpeedCacheMaxFileBytes
	policy.MaxTotalUncompressed = liteSpeedCacheMaxTotal
	if _, err := InspectZIP(ctx, filename, policy); err != nil {
		return "", fmt.Errorf("LiteSpeed Cache 插件归档检查失败: %w", err)
	}
	report, err := ValidateWPComponentPackage(ctx, filename, WPComponentPackageExpectation{
		ComponentType: "plugin", ComponentKey: "litespeed-cache/litespeed-cache.php", OfficialSlug: "litespeed-cache", TargetVersion: version,
	})
	if err != nil {
		return "", fmt.Errorf("LiteSpeed Cache 插件身份检查失败: %w", err)
	}
	zr, err := zip.OpenReader(filename)
	if err != nil {
		return "", err
	}
	defer zr.Close()
	seen := make(map[string]bool)
	var mainHeaders map[string]string
	for _, entry := range zr.File {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		if entry.FileInfo().IsDir() {
			continue
		}
		if entry.Name == "litespeed-cache/litespeed-cache.php" {
			mainHeaders, err = readWPComponentHeaders(entry, "Plugin Name", "Requires at least", "Requires PHP", "Requires Plugins")
			if err != nil {
				return "", err
			}
		}
		name := strings.TrimPrefix(entry.Name, "litespeed-cache/")
		seen[name] = true
		if len(seen) > liteSpeedCacheMaxFiles {
			return "", fmt.Errorf("LiteSpeed Cache 插件文件数量异常")
		}
		if checksums == nil {
			continue
		}
		digest, ok := checksums.Files[name]
		if !ok {
			return "", fmt.Errorf("LiteSpeed Cache 插件包含官方校验清单外的文件")
		}
		rc, err := entry.Open()
		if err != nil {
			return "", err
		}
		hash := sha256.New()
		_, copyErr := io.Copy(hash, liteSpeedCacheContextReader{ctx, rc})
		closeErr := rc.Close()
		if copyErr != nil {
			return "", copyErr
		}
		if closeErr != nil {
			return "", closeErr
		}
		if hex.EncodeToString(hash.Sum(nil)) != digest.SHA256 {
			return "", fmt.Errorf("LiteSpeed Cache 插件文件 SHA-256 校验失败")
		}
	}
	if checksums != nil && len(seen) != len(checksums.Files) {
		return "", fmt.Errorf("LiteSpeed Cache 插件缺少官方校验清单中的文件")
	}
	if mainHeaders["Plugin Name"] != "LiteSpeed Cache" || mainHeaders["Requires Plugins"] != "" {
		return "", fmt.Errorf("LiteSpeed Cache 插件入口身份或依赖无效")
	}
	if err := checkLiteSpeedCacheRequirements(wpVersion, phpVersion, mainHeaders["Requires at least"], mainHeaders["Requires PHP"]); err != nil {
		return "", err
	}
	return report.Inspection.SHA256, nil
}

func checkLiteSpeedCacheRequirements(wpVersion, phpVersion, wpMin, phpMin string) error {
	if !liteSpeedCacheVersionPattern.MatchString(wpVersion) || !liteSpeedCacheVersionPattern.MatchString(phpVersion) {
		return fmt.Errorf("无法确认 LiteSpeed Cache 所需的 WordPress 或 PHP 版本")
	}
	for _, requirement := range []struct{ actual, minimum string }{{wpVersion, wpMin}, {phpVersion, phpMin}} {
		if requirement.minimum == "" {
			continue
		}
		if !liteSpeedCacheVersionPattern.MatchString(requirement.minimum) || compareLiteSpeedCacheVersions(requirement.actual, requirement.minimum) < 0 {
			return fmt.Errorf("LiteSpeed Cache 插件要求的 WordPress 或 PHP 版本不兼容")
		}
	}
	return nil
}

func compareLiteSpeedCacheVersions(actual, required string) int {
	parse := func(value string) [4]int {
		var result [4]int
		for i, part := range strings.Split(value, ".") {
			if i >= len(result) {
				break
			}
			result[i], _ = strconv.Atoi(part)
		}
		return result
	}
	a, b := parse(actual), parse(required)
	for i := range a {
		if a[i] < b[i] {
			return -1
		}
		if a[i] > b[i] {
			return 1
		}
	}
	return 0
}
