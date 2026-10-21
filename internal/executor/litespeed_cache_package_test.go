package executor

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

type liteSpeedCacheTestTransport func(*http.Request) (*http.Response, error)

func (f liteSpeedCacheTestTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func liteSpeedCacheTestZIP(t *testing.T, version, extraHeaders string, extraFiles map[string]string) ([]byte, liteSpeedCacheChecksums) {
	t.Helper()
	files := map[string]string{
		"litespeed-cache.php": "<?php\n/*\nPlugin Name: LiteSpeed Cache\nVersion: " + version + "\n" + extraHeaders + "\n*/\n",
		"readme.txt":          "LiteSpeed Cache fixture\n",
	}
	for name, body := range extraFiles {
		files[name] = body
	}
	checksums := liteSpeedCacheChecksums{Plugin: "litespeed-cache", Version: version}
	checksums.Files = make(map[string]struct {
		SHA256 string `json:"sha256"`
	})
	var out bytes.Buffer
	zw := zip.NewWriter(&out)
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		writer, err := zw.Create("litespeed-cache/" + name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(writer, files[name]); err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256([]byte(files[name]))
		checksums.Files[name] = struct {
			SHA256 string `json:"sha256"`
		}{SHA256: hex.EncodeToString(digest[:])}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes(), checksums
}

func liteSpeedCacheTestJSON(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func liteSpeedCacheTestInfo(version string) liteSpeedCachePluginInfo {
	return liteSpeedCachePluginInfo{Slug: "litespeed-cache", Version: version, DownloadLink: liteSpeedCacheZIPURL(version), Requires: "6.0", RequiresPHP: "7.4"}
}

func liteSpeedCacheTestService(t *testing.T, responses map[string][]byte) (*liteSpeedCachePackageService, *[]string) {
	t.Helper()
	var requests []string
	client := &http.Client{Transport: liteSpeedCacheTestTransport(func(req *http.Request) (*http.Response, error) {
		requests = append(requests, req.URL.String())
		body, exists := responses[req.URL.String()]
		status := http.StatusOK
		if !exists {
			status = http.StatusNotFound
		}
		return &http.Response{StatusCode: status, Request: req, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(body)), ContentLength: int64(len(body))}, nil
	})}
	service := newLiteSpeedCachePackageService(client)
	service.tempDir = t.TempDir()
	return service, &requests
}

func TestLiteSpeedCachePackageLatestStable(t *testing.T) {
	packageBody, checksums := liteSpeedCacheTestZIP(t, "8.0.0.1", "Requires at least: 6.0\nRequires PHP: 7.4", nil)
	service, requests := liteSpeedCacheTestService(t, map[string][]byte{
		liteSpeedCacheMetadataURL:             liteSpeedCacheTestJSON(t, liteSpeedCacheTestInfo("8.0.0.1")),
		liteSpeedCacheChecksumsURL("8.0.0.1"): liteSpeedCacheTestJSON(t, checksums),
		liteSpeedCacheZIPURL("8.0.0.1"):       packageBody,
	})
	pkg, err := service.acquire(context.Background(), "7.1.3", "8.5.2")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(pkg.Path)
	wantSHA := sha256.Sum256(packageBody)
	if pkg.Version != "8.0.0.1" || pkg.Fallback || pkg.SHA256 != hex.EncodeToString(wantSHA[:]) || len(*requests) != 3 {
		t.Fatalf("unexpected package: %+v, requests: %v", pkg, *requests)
	}
	if body, err := os.ReadFile(pkg.Path); err != nil || !bytes.Equal(body, packageBody) {
		t.Fatalf("returned package differs: %v", err)
	}
}

func TestLiteSpeedCachePackageFallsBackWithPinnedSHA256(t *testing.T) {
	pinnedBody, _ := liteSpeedCacheTestZIP(t, liteSpeedCachePinnedVersion, "", nil)
	pinnedSHA := sha256.Sum256(pinnedBody)
	tests := []struct {
		name   string
		mutate func(*liteSpeedCachePluginInfo, *liteSpeedCacheChecksums, map[string][]byte)
	}{
		{name: "API unavailable", mutate: func(_ *liteSpeedCachePluginInfo, _ *liteSpeedCacheChecksums, responses map[string][]byte) {
			delete(responses, liteSpeedCacheMetadataURL)
		}},
		{name: "pre-release", mutate: func(info *liteSpeedCachePluginInfo, _ *liteSpeedCacheChecksums, _ map[string][]byte) {
			info.Version = "8.0-beta1"
		}},
		{name: "older stable", mutate: func(info *liteSpeedCachePluginInfo, _ *liteSpeedCacheChecksums, _ map[string][]byte) {
			info.Version = "7.8.0.1"
			info.DownloadLink = liteSpeedCacheZIPURL(info.Version)
		}},
		{name: "other slug", mutate: func(info *liteSpeedCachePluginInfo, _ *liteSpeedCacheChecksums, _ map[string][]byte) {
			info.Slug = "other"
		}},
		{name: "foreign ZIP URL", mutate: func(info *liteSpeedCachePluginInfo, _ *liteSpeedCacheChecksums, _ map[string][]byte) {
			info.DownloadLink = "https://example.com/plugin.zip"
		}},
		{name: "incompatible WP", mutate: func(info *liteSpeedCachePluginInfo, _ *liteSpeedCacheChecksums, _ map[string][]byte) {
			info.Requires = "99.0"
		}},
		{name: "incompatible PHP", mutate: func(info *liteSpeedCachePluginInfo, _ *liteSpeedCacheChecksums, _ map[string][]byte) {
			info.RequiresPHP = "99.0"
		}},
		{name: "dependency", mutate: func(info *liteSpeedCachePluginInfo, _ *liteSpeedCacheChecksums, _ map[string][]byte) {
			info.RequiresPlugins = []string{"other"}
		}},
		{name: "missing checksums", mutate: func(_ *liteSpeedCachePluginInfo, _ *liteSpeedCacheChecksums, responses map[string][]byte) {
			delete(responses, liteSpeedCacheChecksumsURL("8.0"))
		}},
		{name: "wrong checksum identity", mutate: func(_ *liteSpeedCachePluginInfo, sums *liteSpeedCacheChecksums, _ map[string][]byte) {
			sums.Version = "7.0"
		}},
		{name: "missing SHA256", mutate: func(_ *liteSpeedCachePluginInfo, sums *liteSpeedCacheChecksums, _ map[string][]byte) {
			value := sums.Files["readme.txt"]
			value.SHA256 = ""
			sums.Files["readme.txt"] = value
		}},
		{name: "checksum traversal", mutate: func(_ *liteSpeedCachePluginInfo, sums *liteSpeedCacheChecksums, _ map[string][]byte) {
			sums.Files["../outside.php"] = sums.Files["readme.txt"]
		}},
		{name: "file SHA mismatch", mutate: func(_ *liteSpeedCachePluginInfo, sums *liteSpeedCacheChecksums, _ map[string][]byte) {
			value := sums.Files["readme.txt"]
			value.SHA256 = strings.Repeat("0", 64)
			sums.Files["readme.txt"] = value
		}},
		{name: "ZIP extra file", mutate: func(_ *liteSpeedCachePluginInfo, sums *liteSpeedCacheChecksums, _ map[string][]byte) {
			delete(sums.Files, "readme.txt")
		}},
		{name: "ZIP missing file", mutate: func(_ *liteSpeedCachePluginInfo, sums *liteSpeedCacheChecksums, _ map[string][]byte) {
			sums.Files["missing.php"] = sums.Files["readme.txt"]
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			latestBody, sums := liteSpeedCacheTestZIP(t, "8.0", "", nil)
			info := liteSpeedCacheTestInfo("8.0")
			responses := map[string][]byte{
				liteSpeedCacheMetadataURL:                         {},
				liteSpeedCacheChecksumsURL("8.0"):                 {},
				liteSpeedCacheZIPURL("8.0"):                       latestBody,
				liteSpeedCacheZIPURL(liteSpeedCachePinnedVersion): pinnedBody,
			}
			test.mutate(&info, &sums, responses)
			if _, ok := responses[liteSpeedCacheMetadataURL]; ok {
				responses[liteSpeedCacheMetadataURL] = liteSpeedCacheTestJSON(t, info)
			}
			if _, ok := responses[liteSpeedCacheChecksumsURL("8.0")]; ok {
				responses[liteSpeedCacheChecksumsURL("8.0")] = liteSpeedCacheTestJSON(t, sums)
			}
			service, requests := liteSpeedCacheTestService(t, responses)
			service.pinnedSHA256 = hex.EncodeToString(pinnedSHA[:])
			pkg, err := service.acquire(context.Background(), "7.1.3", "8.5")
			if err != nil {
				t.Fatal(err)
			}
			defer os.Remove(pkg.Path)
			if !pkg.Fallback || pkg.Version != liteSpeedCachePinnedVersion {
				t.Fatalf("expected pinned fallback: %+v", pkg)
			}
			for _, source := range *requests {
				if !validLiteSpeedCacheSource(source) {
					t.Fatalf("untrusted request: %s", source)
				}
			}
			entries, err := os.ReadDir(service.tempDir)
			if err != nil || len(entries) != 1 {
				t.Fatalf("failed candidate leaked temporary files: %v, %v", entries, err)
			}
		})
	}
}

func TestLiteSpeedCachePackageRejectsUnverifiedFallback(t *testing.T) {
	body, _ := liteSpeedCacheTestZIP(t, liteSpeedCachePinnedVersion, "", nil)
	service, _ := liteSpeedCacheTestService(t, map[string][]byte{liteSpeedCacheZIPURL(liteSpeedCachePinnedVersion): body})
	pkg, err := service.acquire(context.Background(), "7.1.3", "8.5")
	if err == nil || pkg.Path != "" || !strings.Contains(err.Error(), "SHA-256") {
		t.Fatalf("unverified fallback accepted: %+v, %v", pkg, err)
	}
	entries, err := os.ReadDir(service.tempDir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("invalid fallback leaked: %v, %v", entries, err)
	}
}

func TestLiteSpeedCachePackageValidatesHeadersAndIdentity(t *testing.T) {
	for _, test := range []struct {
		name, headers string
		files         map[string]string
	}{
		{name: "WP minimum", headers: "Requires at least: 99.0"},
		{name: "PHP minimum", headers: "Requires PHP: 99.0"},
		{name: "malformed requirement", headers: "Requires PHP: not-a-version"},
		{name: "dependency header", headers: "Requires Plugins: other"},
		{name: "version drift", files: map[string]string{"litespeed-cache.php": "<?php\n/*\nPlugin Name: LiteSpeed Cache\nVersion: 7.0\n*/"}},
		{name: "name drift", files: map[string]string{"litespeed-cache.php": "<?php\n/*\nPlugin Name: Other\nVersion: 8.0\n*/"}},
		{name: "traversal", files: map[string]string{"../escape.php": "<?php"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			body, sums := liteSpeedCacheTestZIP(t, "8.0", test.headers, test.files)
			filename := filepath.Join(t.TempDir(), "plugin.zip")
			if err := os.WriteFile(filename, body, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := validateLiteSpeedCachePackage(context.Background(), filename, "8.0", "7.1.3", "8.5", &sums); err == nil {
				t.Fatal("invalid plugin package accepted")
			}
		})
	}
}

func TestLiteSpeedCachePackageHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	service, requests := liteSpeedCacheTestService(t, nil)
	if pkg, err := service.acquire(ctx, "7.1.3", "8.5"); !errors.Is(err, context.Canceled) || pkg.Path != "" || len(*requests) != 0 {
		t.Fatalf("cancelled operation performed requests: %+v, %v, %v", pkg, err, *requests)
	}
	client := &http.Client{Transport: liteSpeedCacheTestTransport(func(req *http.Request) (*http.Response, error) {
		cancel()
		return nil, context.Canceled
	})}
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	service = newLiteSpeedCachePackageService(client)
	if _, err := service.acquire(ctx, "7.1.3", "8.5"); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation converted into fallback: %v", err)
	}
}

func TestLiteSpeedCachePackageRejectsRedirectsAndFinalURLDrift(t *testing.T) {
	for _, drift := range []bool{false, true} {
		var requests int
		service := newLiteSpeedCachePackageService(&http.Client{Transport: liteSpeedCacheTestTransport(func(req *http.Request) (*http.Response, error) {
			requests++
			resp := &http.Response{StatusCode: http.StatusFound, Request: req, Header: http.Header{"Location": {"https://example.com/plugin.zip"}}, Body: io.NopCloser(strings.NewReader(""))}
			if drift {
				foreignURL, _ := url.Parse("https://example.com/plugin.zip")
				copyRequest := req.Clone(req.Context())
				copyRequest.URL = foreignURL
				resp.Request = copyRequest
				resp.StatusCode = http.StatusOK
			}
			return resp, nil
		})})
		if _, err := service.request(context.Background(), liteSpeedCacheMetadataURL); err == nil || requests != 1 {
			t.Fatalf("redirect or final URL drift accepted: %v, requests: %d", err, requests)
		}
	}
}

func TestLiteSpeedCachePackageBoundsResponses(t *testing.T) {
	service, _ := liteSpeedCacheTestService(t, map[string][]byte{
		liteSpeedCacheMetadataURL:   []byte(strings.Repeat(" ", liteSpeedCacheMaxJSONBytes+1)),
		liteSpeedCacheZIPURL("8.0"): []byte(strings.Repeat("z", liteSpeedCacheMaxZIPBytes+1)),
	})
	if err := service.getJSON(context.Background(), liteSpeedCacheMetadataURL, &liteSpeedCachePluginInfo{}); err == nil {
		t.Fatal("oversized JSON accepted")
	}
	if name, err := service.download(context.Background(), liteSpeedCacheZIPURL("8.0")); err == nil || name != "" {
		t.Fatalf("oversized package accepted: %s, %v", name, err)
	}
	chunked := newLiteSpeedCachePackageService(&http.Client{Transport: liteSpeedCacheTestTransport(func(req *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Request: req, Header: make(http.Header), ContentLength: -1, Body: io.NopCloser(strings.NewReader(strings.Repeat("z", liteSpeedCacheMaxZIPBytes+1)))}, nil
	})})
	chunked.tempDir = t.TempDir()
	if name, err := chunked.download(context.Background(), liteSpeedCacheZIPURL("8.0")); err == nil || name != "" {
		t.Fatalf("oversized chunked package accepted: %s, %v", name, err)
	}
	entries, err := os.ReadDir(chunked.tempDir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("oversized chunked package retained: %v, %v", entries, err)
	}
}

func TestLiteSpeedCacheSourceAndVersionRules(t *testing.T) {
	for _, source := range []string{
		"http://downloads.wordpress.org/plugin/litespeed-cache.8.0.zip",
		"https://downloads.wordpress.org:443/plugin/litespeed-cache.8.0.zip",
		"https://downloads.wordpress.org/plugin/litespeed-cache.8.0.zip?x=1",
		"https://downloads.wordpress.org/plugin/litespeed-cache.8.0.zip#fragment",
		"https://downloads.wordpress.org/plugin/litespeed-cache.8.0-beta.zip",
		"https://downloads.wordpress.org/plugins/litespeed-cache.8.0.zip",
		"https://downloads.wordpress.org/plugin/other.8.0.zip",
		"https://user@downloads.wordpress.org/plugin/litespeed-cache.8.0.zip",
	} {
		if validLiteSpeedCacheSource(source) {
			t.Fatalf("unsafe source accepted: %s", source)
		}
	}
	if compareLiteSpeedCacheVersions("7.9.2.1", "7.9.2") <= 0 || compareLiteSpeedCacheVersions("7.9.10", "7.9.2") <= 0 || compareLiteSpeedCacheVersions("7.9.2", "7.9.2.1") >= 0 {
		t.Fatal("numeric version ordering is incorrect")
	}
	service, requests := liteSpeedCacheTestService(t, nil)
	for _, version := range []string{"", "7.1-rc1", "7.1.2.3.4"} {
		if _, err := service.acquire(context.Background(), version, "8.5"); err == nil {
			t.Fatalf("unconfirmed runtime version accepted: %s", version)
		}
	}
	if len(*requests) != 0 {
		t.Fatal("invalid runtime versions triggered downloads")
	}
}
