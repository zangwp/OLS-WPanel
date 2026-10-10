package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOfficialWordPressDownloadOriginIsBoundToAcquiredArchiveAndClearedByUpload(t *testing.T) {
	body, err := os.ReadFile(validWordPressZIP(t))
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "wordpress.zip")
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.String() != wordpressLatestURL {
			t.Fatalf("unexpected request %s", req.URL)
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(body)), Header: make(http.Header), Request: req}, nil
	})}
	service, err := NewWPPackageService(target, client)
	if err != nil {
		t.Fatal(err)
	}
	report, err := service.DownloadLatest(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if !report.OfficialDownload || report.Verification != "structure_only" {
		t.Fatalf("download provenance must not change checksum-verification level: %+v", report)
	}
	origin, err := os.ReadFile(target + ".origin.json")
	if err != nil {
		t.Fatal(err)
	}
	acquire := func(wantOfficial bool) {
		t.Helper()
		report, usedCache, err := AcquireCorePackage(t.Context(), target, filepath.Join(t.TempDir(), "copy.zip"), "", func(context.Context) error {
			t.Fatal("provenance lookup must not cause a network refresh")
			return nil
		})
		if err != nil || !usedCache || report.OfficialDownload != wantOfficial {
			t.Fatalf("actual copied ZIP provenance = %v, want %v; usedCache=%v err=%v", report.OfficialDownload, wantOfficial, usedCache, err)
		}
	}
	acquire(true)
	// Even uploading an identical archive intentionally stops automatic
	// cleanup. The service must not reuse its prior official-source receipt.
	report, err = service.PublishUpload(t.Context(), bytes.NewReader(body), int64(len(body)))
	if err != nil || report.OfficialDownload {
		t.Fatalf("upload acquired official download provenance: %+v, %v", report, err)
	}
	acquire(false)
	// Restore a stale receipt then replace the ZIP with a customized package
	// having the same version/locale. Only the actual complete hash qualifies.
	if err := os.WriteFile(target+".origin.json", origin, 0600); err != nil {
		t.Fatal(err)
	}
	custom := writeTestZIP(t, map[string]string{
		"wordpress/wp-admin/index.php":                           "<?php",
		"wordpress/wp-includes/load.php":                         "<?php",
		"wordpress/wp-includes/version.php":                      "<?php\n$wp_version = '7.0.2';\n$wp_local_package = 'zh_CN';\n",
		"wordpress/wp-settings.php":                              "<?php",
		"wordpress/wp-load.php":                                  "<?php",
		"wordpress/wp-content/plugins/akismet/akismet.php":       "customized-akismet",
		"wordpress/wp-content/themes/twentytwentyfour/style.css": "customized-theme",
	})
	if err := copyFile(custom, target); err != nil {
		t.Fatal(err)
	}
	acquire(false)
}

func TestWordPressPackageOriginRejectsMissingMalformedOrMismatchedReceipt(t *testing.T) {
	cache := validWordPressZIP(t)
	report, err := ValidateWordPressPackage(t.Context(), cache)
	if err != nil {
		t.Fatal(err)
	}
	valid := wordPressPackageOrigin{SourceURL: wordpressLatestURL, SHA256: report.Inspection.SHA256, ArchiveBytes: report.Inspection.ArchiveBytes}
	encode := func(origin wordPressPackageOrigin) []byte {
		body, err := json.Marshal(origin)
		if err != nil {
			t.Fatal(err)
		}
		return body
	}
	wrongSource, wrongHash, wrongSize := valid, valid, valid
	wrongSource.SourceURL = "https://example.com/latest.zip"
	wrongHash.SHA256 = strings.Repeat("0", 64)
	wrongSize.ArchiveBytes++
	for _, fixture := range []struct {
		name string
		body []byte
		want bool
	}{
		{"matching", encode(valid), true},
		{"missing", nil, false},
		{"malformed", []byte("{"), false},
		{"trailing document", append(encode(valid), []byte("{}")...), false},
		{"too large", append(encode(valid), []byte(strings.Repeat(" ", 4096))...), false},
		{"wrong source", encode(wrongSource), false},
		{"wrong hash", encode(wrongHash), false},
		{"wrong size", encode(wrongSize), false},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			path := cache + ".origin.json"
			_ = os.Remove(path)
			if fixture.body != nil {
				if err := os.WriteFile(path, fixture.body, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if got := wordPressPackageHasOfficialOrigin(cache, report); got != fixture.want {
				t.Fatalf("eligible=%v, want=%v", got, fixture.want)
			}
		})
	}
	t.Run("symlink", func(t *testing.T) {
		path := cache + ".origin.json"
		_ = os.Remove(path)
		other := filepath.Join(t.TempDir(), "origin.json")
		if err := os.WriteFile(other, encode(valid), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(other, path); err != nil {
			t.Skipf("host does not permit symlink fixture: %v", err)
		}
		if wordPressPackageHasOfficialOrigin(cache, report) {
			t.Fatal("symlink receipt was accepted")
		}
	})
}

func TestWordPressPackageOriginWriteFailureDoesNotPreventOfficialDownload(t *testing.T) {
	body, err := os.ReadFile(validWordPressZIP(t))
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "wordpress.zip")
	if err := os.Mkdir(target+".origin.json", 0755); err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(body)), Header: make(http.Header), Request: req}, nil
	})}
	service, err := NewWPPackageService(target, client)
	if err != nil {
		t.Fatal(err)
	}
	report, err := service.DownloadLatest(t.Context())
	if err != nil || report.OfficialDownload {
		t.Fatalf("valid download should remain available with cleanup disabled: %+v %v", report, err)
	}
	if _, err := ValidateWordPressPackage(t.Context(), target); err != nil {
		t.Fatalf("valid archive unavailable after optional receipt failure: %v", err)
	}
}

func TestUploadCannotKeepAnOldOfficialReceiptWhenInvalidationFails(t *testing.T) {
	body, err := os.ReadFile(validWordPressZIP(t))
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "wordpress.zip")
	if err := os.WriteFile(target, []byte("original cache"), 0644); err != nil {
		t.Fatal(err)
	}
	// A nonempty directory is an OS-independent invalidation failure. The
	// prior archive must remain intact rather than publishing an ambiguous upload.
	if err := os.Mkdir(target+".origin.json", 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target+".origin.json", "blocker"), []byte("keep"), 0644); err != nil {
		t.Fatal(err)
	}
	service, err := NewWPPackageService(target, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.PublishUpload(t.Context(), bytes.NewReader(body), int64(len(body))); ArchiveErrorCode(err) != "package_publish_failed" {
		t.Fatalf("unsafe upload publication succeeded: %v", err)
	}
	original, err := os.ReadFile(target)
	if err != nil || string(original) != "original cache" {
		t.Fatalf("old archive changed after receipt invalidation failed: %s, %v", original, err)
	}
}
