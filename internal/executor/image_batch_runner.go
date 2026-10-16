package executor

import (
	"context"
	"crypto/rand"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/zangwp/OLS-WPanel/internal/config"
)

//go:embed assets/image-filesize-runner/filesize_runner.php
var imageFilesizeRunnerPHPSource []byte

// imageBatchBinaryArgs fixes the allowed binaries and arguments; request input cannot change them.
// This allowlist, target path validation, and privilege dropping form the security boundary,
// independent of commander.go's allowedCommands (ADR-0003, decision 2).
// Keep EXIF/ICC and strip only comments/IPTC/XMP. --strip-all would remove orientation tags
// from older or migrated JPEGs whose pixels were never rotated, permanently changing their display.
var imageBatchBinaryArgs = map[string][]string{
	"jpegoptim": {"--strip-com", "--strip-iptc", "--strip-xmp"},
	"optipng":   {"-o2", "-quiet"},
}

const (
	imageBatchRuntimeRoot  = "/var/ols-wpanel/image-optimizer"
	imageBatchExecTimeout  = 30 * time.Second
	imageBatchOutputLimit  = 64 << 10
	imageFilesizeTimeout   = 60 * time.Second
	imageFilesizeResultMax = 4 << 10
)

// lookupSiteSystemUser shares validated UID/GID lookup between optimization and filesize writeback.
//
// Callers validate the wp_ prefix with wpInventoryUserPattern, and website_tasks.go
// generates the same prefix, so systemUser cannot be misinterpreted as a numeric UID.
func lookupSiteSystemUser(systemUser string) (*user.User, int, int, error) {
	u, err := user.Lookup(systemUser)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("查找站点系统用户失败: %w", err)
	}
	uid, err1 := strconv.Atoi(u.Uid)
	gid, err2 := strconv.Atoi(u.Gid)
	if err1 != nil || err2 != nil || uid <= 0 || gid <= 0 {
		return nil, 0, 0, errors.New("站点系统用户身份异常")
	}
	return u, uid, gid, nil
}

func binaryForMime(mime string) string {
	switch mime {
	case "image/jpeg":
		return "jpegoptim"
	case "image/png":
		return "optipng"
	default:
		return ""
	}
}

// optimizeImageFile losslessly re-encodes an upload in place using the privilege-drop pattern
// from wp_core_update_runner.go: resolve the site user, validate the binary, then run as that user.
//
// modUnix is the mtime after re-encoding. Callers must store it in the fingerprint;
// the old scan mtime would cause every rewritten file to be processed again next time.
func optimizeImageFile(ctx context.Context, webRoot, systemUser, relativePath, mime string) (before, after, modUnix int64, err error) {
	binaryName := binaryForMime(mime)
	if binaryName == "" {
		return 0, 0, 0, fmt.Errorf("不支持的图片类型: %s", mime)
	}
	fixedArgs, ok := imageBatchBinaryArgs[binaryName]
	if !ok {
		return 0, 0, 0, fmt.Errorf("未登记的二进制: %s", binaryName)
	}

	if os.Geteuid() != 0 {
		return 0, 0, 0, errors.New("图片优化 runner 需要 root 权限")
	}
	if !wpInventoryUserPattern.MatchString(systemUser) {
		return 0, 0, 0, errors.New("站点系统用户格式非法")
	}

	wwwRoot := config.AppConfig.Paths.WWWRoot
	siteRoot, err := validateInventorySitePath(wwwRoot, webRoot)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("站点目录校验失败: %w", err)
	}

	absPath, err := validateImageBatchFilePath(siteRoot, relativePath)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("文件路径校验失败: %w", err)
	}

	beforeInfo, err := os.Stat(absPath)
	if err != nil {
		return 0, 0, 0, err
	}
	before = beforeInfo.Size()

	u, _, _, err := lookupSiteSystemUser(systemUser)
	if err != nil {
		return 0, 0, 0, err
	}

	binaryPath, err := validateInventoryBinary("/usr/bin/"+binaryName, "/usr/bin", 0, 0)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("%s 二进制校验失败: %w", binaryName, err)
	}
	runuserPath, err := validateInventoryBinary(wpInventoryRunuserPath, "/usr/sbin", 0, 0)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("runuser 校验失败: %w", err)
	}

	args := append([]string{"-u", u.Username, "--", binaryPath}, fixedArgs...)
	args = append(args, absPath)

	execCtx, cancel := context.WithTimeout(ctx, imageBatchExecTimeout)
	defer cancel()
	cmd := exec.CommandContext(execCtx, runuserPath, args...)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C.UTF-8", "LC_ALL=C.UTF-8"}
	out, outputExceeded, runErr := runImageBatchCommand(cmd)
	if outputExceeded {
		return before, before, beforeInfo.ModTime().Unix(), fmt.Errorf("%s 输出超过限制", binaryName)
	}
	if runErr != nil {
		return before, before, beforeInfo.ModTime().Unix(), fmt.Errorf("%s 执行失败: %w\n%s", binaryName, runErr, string(out))
	}

	afterInfo, err := os.Stat(absPath)
	if err != nil {
		return before, before, beforeInfo.ModTime().Unix(), err
	}
	after = afterInfo.Size()
	// Report unexpected file growth so the caller can decide whether to treat it as a failure.
	return before, after, afterInfo.ModTime().Unix(), nil
}

func runImageBatchCommand(cmd *exec.Cmd) ([]byte, bool, error) {
	output := newCountingSink(imageBatchOutputLimit, true)
	cmd.Stdout, cmd.Stderr = output, output
	err := cmd.Run()
	_, exceeded, kept := output.snapshot()
	return kept, exceeded, err
}

func validateImageBatchFilePath(siteRoot, relativePath string) (string, error) {
	relativePath = filepath.Clean("/" + relativePath)
	absPath := filepath.Join(siteRoot, "wp-content", "uploads", relativePath)
	uploadsRoot := filepath.Join(siteRoot, "wp-content", "uploads")

	info, err := os.Lstat(absPath)
	if err != nil {
		return "", err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return "", errors.New("目标不是普通文件")
	}
	real, err := filepath.EvalSymlinks(absPath)
	if err != nil {
		return "", err
	}
	if !pathWithin(uploadsRoot, real, false) {
		return "", errors.New("文件路径逃逸出 uploads 目录")
	}
	return real, nil
}

type imageFilesizeResult struct {
	Token     string `json:"token"`
	OK        bool   `json:"ok"`
	Updated   int    `json:"updated"`
	Total     int    `json:"total"`
	ErrorCode string `json:"error_code"`
}

// runFilesizeRewrite passes relative paths and sizes to PHP running as the site user.
// The script uses WordPress update_post_meta(); direct SQL could corrupt PHP-serialized attachment metadata.
func runFilesizeRewrite(ctx context.Context, webRoot, systemUser string, manifest map[string]int64) (updated, total int, err error) {
	if len(manifest) == 0 {
		return 0, 0, nil
	}
	if os.Geteuid() != 0 {
		return 0, 0, errors.New("filesize runner 需要 root 权限")
	}
	if !wpInventoryUserPattern.MatchString(systemUser) {
		return 0, 0, errors.New("站点系统用户格式非法")
	}

	wwwRoot := config.AppConfig.Paths.WWWRoot
	siteRoot, err := validateInventorySitePath(wwwRoot, webRoot)
	if err != nil {
		return 0, 0, fmt.Errorf("站点目录校验失败: %w", err)
	}

	u, uid, gid, err := lookupSiteSystemUser(systemUser)
	if err != nil {
		return 0, 0, err
	}

	phpPath, err := validateInventoryBinary(LSPHPBinaryPath(), filepath.Dir(LSPHPBinaryPath()), 0, 0)
	if err != nil {
		return 0, 0, err
	}
	runuserPath, err := validateInventoryBinary(wpInventoryRunuserPath, "/usr/sbin", 0, 0)
	if err != nil {
		return 0, 0, err
	}

	if err := os.MkdirAll(imageBatchRuntimeRoot, 0711); err != nil {
		return 0, 0, err
	}
	tokenBytes := make([]byte, 16)
	if _, err := rand.Read(tokenBytes); err != nil {
		return 0, 0, err
	}
	token := hex.EncodeToString(tokenBytes)
	runtimeDir := filepath.Join(imageBatchRuntimeRoot, token)
	if filepath.Dir(runtimeDir) != filepath.Clean(imageBatchRuntimeRoot) || os.Mkdir(runtimeDir, 0710) != nil {
		return 0, 0, errors.New("创建运行目录失败")
	}
	defer func() { _ = os.RemoveAll(runtimeDir) }()
	if err := os.Chown(runtimeDir, 0, gid); err != nil {
		return 0, 0, err
	}

	manifestPath := filepath.Join(runtimeDir, "manifest.json")
	manifestJSON, err := json.Marshal(manifest)
	if err != nil {
		return 0, 0, err
	}
	if err := writeOwnedFile(manifestPath, manifestJSON, uid, gid); err != nil {
		return 0, 0, err
	}
	resultPath := filepath.Join(runtimeDir, "result.json")
	if err := createWPPluginRunnerResult(resultPath, uid, gid); err != nil {
		return 0, 0, err
	}

	openBase := strings.Join([]string{siteRoot, runtimeDir, "/tmp", "/usr/share/php"}, ":")
	execCtx, cancel := context.WithTimeout(ctx, imageFilesizeTimeout)
	defer cancel()
	args := []string{"-u", u.Username, "--", "/usr/bin/env", "-i",
		"PATH=/usr/bin:/bin", "LANG=C.UTF-8", "LC_ALL=C.UTF-8", "HOME=" + u.HomeDir, "USER=" + u.Username, "LOGNAME=" + u.Username, "TMPDIR=/tmp",
		phpPath,
		"-d", "open_basedir=" + openBase,
		"-d", "disable_functions=" + sitePHPDisabledFunctions(),
		"-d", "allow_url_include=0",
		"-d", "memory_limit=256M",
		"-r", string(imageFilesizeRunnerPHPSource),
		token, siteRoot, manifestPath, resultPath,
	}
	cmd := exec.CommandContext(execCtx, runuserPath, args...)
	if runErr := cmd.Run(); runErr != nil && !errors.Is(execCtx.Err(), context.DeadlineExceeded) {
		// PHP may have written the result before exiting with an error; still try to read it.
	}

	result, err := readImageFilesizeResult(resultPath, token)
	if err != nil {
		return 0, 0, err
	}
	if !result.OK {
		return 0, 0, fmt.Errorf("filesize 回写失败: %s", result.ErrorCode)
	}
	return result.Updated, result.Total, nil
}

func writeOwnedFile(name string, data []byte, uid, gid int) error {
	f, err := os.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := f.Chown(uid, gid); err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		return err
	}
	return f.Sync()
}

func readImageFilesizeResult(name, token string) (imageFilesizeResult, error) {
	info, err := os.Lstat(name)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Size() <= 0 || info.Size() > imageFilesizeResultMax {
		return imageFilesizeResult{}, errors.New("filesize 回写结果无效")
	}
	raw, err := os.ReadFile(name)
	if err != nil {
		return imageFilesizeResult{}, err
	}
	var result imageFilesizeResult
	if err := json.Unmarshal(raw, &result); err != nil || result.Token != token {
		return imageFilesizeResult{}, errors.New("filesize 回写结果 token 不匹配")
	}
	return result, nil
}
