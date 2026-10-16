package executor

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/zangwp/OLS-WPanel/internal/config"
)

// imageBatchCandidate is an image awaiting batch optimization.
type imageBatchCandidate struct {
	RelativePath string // Slash-separated path relative to wp-content/uploads/.
	AbsPath      string
	Mime         string
	Size         int64
	ModUnix      int64
}

// scanSiteUploadsForImages returns regular JPEG/PNG uploads and rejects symlinks via Lstat.
// Privilege dropping limits writes to the site user, but a compromised site could link uploads
// to sensitive files such as wp-config.php and trick the optimizer into rewriting them.
// See validateInventorySitePath in wp_inventory_runner.go.
func scanSiteUploadsForImages(webRoot string) ([]imageBatchCandidate, error) {
	wwwRoot := config.AppConfig.Paths.WWWRoot
	siteRoot, err := validateInventorySitePath(wwwRoot, webRoot)
	if err != nil {
		return nil, err
	}
	uploadsRoot := filepath.Join(siteRoot, "wp-content", "uploads")
	realUploadsRoot, err := filepath.EvalSymlinks(uploadsRoot)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	if !pathWithin(siteRoot, realUploadsRoot, true) {
		return nil, os.ErrInvalid
	}

	var candidates []imageBatchCandidate
	err = filepath.WalkDir(realUploadsRoot, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil // Skip unreadable entries without aborting the scan.
		}
		if d.IsDir() {
			// Do not traverse symlinked directories outside the uploads tree.
			if info, statErr := os.Lstat(path); statErr == nil && info.Mode()&os.ModeSymlink != 0 {
				return filepath.SkipDir
			}
			return nil
		}

		info, statErr := os.Lstat(path)
		if statErr != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return nil
		}

		ext := strings.ToLower(filepath.Ext(path))
		var mime string
		switch ext {
		case ".jpg", ".jpeg":
			mime = "image/jpeg"
		case ".png":
			mime = "image/png"
		default:
			return nil
		}

		real, err := filepath.EvalSymlinks(path)
		if err != nil || !pathWithin(realUploadsRoot, real, false) {
			return nil
		}

		// Extensions select the optimizer; magic bytes establish whether the file is an image.
		// Skip invalid headers so disguised files are not repeatedly attempted and counted as failures.
		if !hasImageMagicBytes(real, mime) {
			return nil
		}

		rel, err := filepath.Rel(realUploadsRoot, real)
		if err != nil {
			return nil
		}
		candidates = append(candidates, imageBatchCandidate{
			RelativePath: filepath.ToSlash(rel),
			AbsPath:      real,
			Mime:         mime,
			Size:         info.Size(),
			ModUnix:      info.ModTime().Unix(),
		})
		return nil
	})
	if err != nil {
		return nil, err
	}
	return candidates, nil
}

var (
	jpegMagic = []byte{0xFF, 0xD8, 0xFF}
	pngMagic  = []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}
)

func hasImageMagicBytes(path, mime string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	header := make([]byte, 8)
	n, _ := io.ReadFull(f, header)
	switch mime {
	case "image/jpeg":
		return n >= len(jpegMagic) && bytes.Equal(header[:len(jpegMagic)], jpegMagic)
	case "image/png":
		return n >= len(pngMagic) && bytes.Equal(header[:len(pngMagic)], pngMagic)
	default:
		return false
	}
}
