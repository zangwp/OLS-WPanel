package executor

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
)

type wordPressPackageOrigin struct {
	SourceURL    string `json:"source_url"`
	SHA256       string `json:"sha256"`
	ArchiveBytes int64  `json:"archive_bytes"`
}

func wordPressPackageHasOfficialOrigin(cachePath string, report WPPackageReport) bool {
	path := cachePath + ".origin.json"
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 4096 {
		return false
	}
	file, err := os.Open(path)
	if err != nil {
		return false
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || opened.Size() > 4096 || !os.SameFile(info, opened) {
		return false
	}
	encoded, err := io.ReadAll(io.LimitReader(file, 4097))
	if err != nil || len(encoded) > 4096 {
		return false
	}
	var origin wordPressPackageOrigin
	if json.Unmarshal(encoded, &origin) != nil {
		return false
	}
	return origin.SourceURL == wordpressLatestURL &&
		len(origin.SHA256) == 64 && origin.SHA256 == report.Inspection.SHA256 &&
		origin.ArchiveBytes > 0 && origin.ArchiveBytes == report.Inspection.ArchiveBytes
}

// A failed receipt is optional metadata: it must never prevent a valid
// package from being used. An upload writes an empty source so even an
// identical ZIP deliberately uploaded by the user is conservatively kept.
func writeWordPressPackageOrigin(cachePath string, report WPPackageReport, sourceURL string) (retErr error) {
	defer func() {
		if retErr != nil {
			log.Printf("WordPress package origin receipt unavailable; fresh-install default cleanup may be skipped: %v", retErr)
		}
	}()
	encoded, err := json.Marshal(wordPressPackageOrigin{SourceURL: sourceURL, SHA256: report.Inspection.SHA256, ArchiveBytes: report.Inspection.ArchiveBytes})
	if err != nil {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(cachePath), ".wordpress-origin-*.tmp")
	if err != nil {
		return err
	}
	name := file.Name()
	defer os.Remove(name)
	if err := file.Chmod(0600); err != nil {
		file.Close()
		return err
	}
	if _, err := file.Write(encoded); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, cachePath+".origin.json"); err != nil {
		return fmt.Errorf("publish origin receipt: %w", err)
	}
	return nil
}
