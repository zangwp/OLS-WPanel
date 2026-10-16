package executor

import (
	"context"
	"log"
	"os/exec"
	"strings"
	"time"
)

func primaryPHPExifPackage() string {
	return "lsphp" + strings.ReplaceAll(PrimaryLSPHPVersion(), ".", "") + "-common"
}

// jpegoptimPackage/optipngPackage support existing-image optimization.
// LSPHP EXIF support separately handles new uploads.
const jpegoptimPackage = "jpegoptim"
const optipngPackage = "optipng"

// EnsurePHPExifExtension installs LSPHP common for EXIF orientation correction on new uploads.
// install.sh handles new servers; this asynchronous backfill restarts lshttpd on existing servers.
// The plugin checks is_callable('exif_read_data') at runtime, so the next page load detects installation.
func EnsurePHPExifExtension() {
	phpExifPackage := primaryPHPExifPackage()
	ensureAptPackage(phpExifPackage, func() {
		if err := ReloadOpenLiteSpeed(); err != nil {
			log.Printf("[图片优化] %s 补装成功，但重启 OpenLiteSpeed/LSPHP 失败，需要人工重启使扩展生效: %v", phpExifPackage, err)
			return
		}
		log.Printf("[图片优化] 已补装 %s 并重启 OpenLiteSpeed/LSPHP", phpExifPackage)
	})
}

// EnsureImageBatchBinaries installs jpegoptim/optipng for batch image optimization.
// No service reload is needed; ImageBatchBinariesReady detects them on the next scan.
func EnsureImageBatchBinaries() {
	ensureAptPackage(jpegoptimPackage, nil)
	ensureAptPackage(optipngPackage, nil)
}

// ImageBatchBinariesReady reports whether both batch optimization binaries are available.
func ImageBatchBinariesReady() bool {
	return binaryInPath(jpegoptimPackage) && binaryInPath(optipngPackage)
}

func ensureAptPackage(pkg string, onInstalled func()) {
	if aptPackageInstalled(pkg) {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, "apt-get", "install", "-y",
		"-o", "DPkg::Lock::Timeout=60",
		pkg)
	out, err := cmd.CombinedOutput()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			log.Printf("[图片优化] 补装 %s 超时（3 分钟），后续面板重启会重试", pkg)
			return
		}
		log.Printf("[图片优化] 补装 %s 失败: %v\n%s", pkg, err, string(out))
		return
	}

	if onInstalled != nil {
		onInstalled()
		return
	}
	log.Printf("[图片优化] 已补装 %s", pkg)
}

func aptPackageInstalled(pkg string) bool {
	return exec.Command("dpkg", "-s", pkg).Run() == nil
}

func binaryInPath(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}
