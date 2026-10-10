package tests

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func installerWordPressPHP(t *testing.T, name, next string) string {
	t.Helper()
	helper := extractShellFunction(t, readInstallScript(t, installScriptPath), name, next)
	start := strings.Index(helper, "-r '\n")
	end := strings.LastIndex(helper, "\n' \"")
	if start < 0 || end < start {
		t.Fatalf("missing real PHP body in %s", name)
	}
	return helper[start+len("-r '\n") : end]
}

func installerWordPressPHPRuntime(t *testing.T, needsZIP bool) (string, []string) {
	t.Helper()
	php, err := exec.LookPath("php")
	if err != nil {
		t.Skip("PHP CLI unavailable")
	}
	args := []string{"-n"}
	if needsZIP {
		probe := exec.Command(php, "-r", `exit(class_exists("ZipArchive") ? 0 : 1);`)
		if probe.Run() == nil {
			args = nil
		} else if runtime.GOOS == "windows" {
			args = append(args, "-d", "extension_dir="+filepath.Join(filepath.Dir(php), "ext"), "-d", "extension=zip")
		} else {
			t.Skip("PHP ZipArchive unavailable")
		}
		if err := exec.Command(php, append(append([]string{}, args...), "-r", `exit(class_exists("ZipArchive") ? 0 : 1);`)...).Run(); err != nil {
			t.Fatalf("real ZipArchive runtime unavailable: %v", err)
		}
	}
	return php, args
}

func TestInstallerWordPressDownloadRestrictsEveryHTTPSRedirect(t *testing.T) {
	php, flags := installerWordPressPHPRuntime(t, false)
	body := installerWordPressPHP(t, "download_official_wordpress_archive", "validate_installer_wordpress_archive")
	const stub = `
$fixture = json_decode(file_get_contents("php://stdin"), true);
foreach (array("CURLOPT_FOLLOWLOCATION", "CURLOPT_PROTOCOLS", "CURLPROTO_HTTPS", "CURLOPT_SSL_VERIFYPEER", "CURLOPT_SSL_VERIFYHOST", "CURLOPT_CONNECTTIMEOUT", "CURLOPT_TIMEOUT", "CURLOPT_FAILONERROR", "CURLOPT_HEADERFUNCTION", "CURLOPT_WRITEFUNCTION", "CURLINFO_RESPONSE_CODE") as $index => $name) { define($name, $index + 1); }
function curl_init($url) {
    file_put_contents($GLOBALS["fixture"]["requests"], $url . "\n", FILE_APPEND);
    return (object) array("url" => $url, "options" => array(), "status" => 0);
}
function curl_setopt_array($curl, $options) { $curl->options = $options; return true; }
function curl_exec($curl) {
    $response = array_shift($GLOBALS["fixture"]["responses"]);
    if (!$response || isset($response["error"])) { return false; }
    $curl->status = $response["status"];
    $header = $curl->options[CURLOPT_HEADERFUNCTION];
    if (!$header($curl, "HTTP/1.1 " . $curl->status . "\r\n")) { return false; }
    if (isset($response["location"]) && !$header($curl, "Location: " . $response["location"] . "\r\n")) { return false; }
    $data = $response["body"] ?? "redirect body";
    return $curl->options[CURLOPT_WRITEFUNCTION]($curl, $data) === strlen($data);
}
function curl_getinfo($curl, $option) { return $curl->status; }
function curl_close($curl) {}
`
	response := func(location string) map[string]any { return map[string]any{"status": 302, "location": location} }
	for _, tc := range []struct {
		name      string
		responses []map[string]any
		allowed   bool
		calls     int
	}{
		{"direct official", []map[string]any{{"status": 200, "body": "original ZIP"}}, true, 1},
		{"official package redirect", []map[string]any{response("https://downloads.wordpress.org/release/package.zip"), {"status": 200, "body": "original ZIP"}}, true, 2},
		{"relative HTTPS redirect", []map[string]any{response("/release/package.zip"), {"status": 200, "body": "original ZIP"}}, true, 2},
		{"HTTP downgrade", []map[string]any{response("http://downloads.wordpress.org/package.zip")}, false, 1},
		{"foreign HTTPS host", []map[string]any{response("https://example.invalid/package.zip")}, false, 1},
		{"protocol relative foreign host", []map[string]any{response("//example.invalid/package.zip")}, false, 1},
		{"host suffix spoof", []map[string]any{response("https://wordpress.org.evil.invalid/package.zip")}, false, 1},
		{"credentials", []map[string]any{response("https://user@wordpress.org/package.zip")}, false, 1},
		{"unexpected port", []map[string]any{response("https://wordpress.org:8443/package.zip")}, false, 1},
		{"oversized body", []map[string]any{{"status": 200, "body": strings.Repeat("X", 65)}}, false, 1},
		{"empty body", []map[string]any{{"status": 200, "body": ""}}, false, 1},
		{"failed HTTP response", []map[string]any{{"status": 503}}, false, 1},
		{"redirect loop", []map[string]any{response("/a"), response("/a"), response("/a"), response("/a"), response("/a"), response("/a")}, false, 6},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			outPath, requests := filepath.Join(root, "download.zip"), filepath.Join(root, "requests.log")
			fixture, _ := json.Marshal(map[string]any{"responses": tc.responses, "requests": requests})
			args := append(append([]string{}, flags...), "-r", stub+body, outPath, "64")
			cmd := exec.Command(php, args...)
			cmd.Stdin = bytes.NewReader(fixture)
			out, err := cmd.CombinedOutput()
			if (err == nil) != tc.allowed {
				t.Fatalf("allowed=%t error=%v output=%s", tc.allowed, err, out)
			}
			actual, err := os.ReadFile(requests)
			if err != nil || len(strings.Fields(string(actual))) != tc.calls || !strings.HasPrefix(string(actual), "https://wordpress.org/latest.zip\n") {
				t.Fatalf("unexpected request trace: %s (%v)", actual, err)
			}
			if tc.allowed {
				data, _ := os.ReadFile(outPath)
				if string(data) != "original ZIP" {
					t.Fatal("redirect response body was included in the downloaded package")
				}
			}
		})
	}
}

func TestInstallerWordPressArchiveValidationUsesRealZIP(t *testing.T) {
	php, flags := installerWordPressPHPRuntime(t, true)
	body := installerWordPressPHP(t, "validate_installer_wordpress_archive", "write_wordpress_origin_receipt")
	for _, scenario := range []string{"valid", "html", "missing core", "traversal", "foreign root", "symlink", "invalid version"} {
		t.Run(scenario, func(t *testing.T) {
			name := filepath.Join(t.TempDir(), "wordpress.zip")
			var buf bytes.Buffer
			zw := zip.NewWriter(&buf)
			files := map[string]string{"wordpress/wp-includes/version.php": "<?php $wp_version = '6.8.2';", "wordpress/wp-settings.php": "<?php", "wordpress/wp-load.php": "<?php", "wordpress/wp-admin/index.php": "<?php", "wordpress/wp-includes/load.php": "<?php"}
			switch scenario {
			case "missing core":
				delete(files, "wordpress/wp-settings.php")
			case "traversal":
				files["wordpress/../outside.php"] = "custom"
			case "foreign root":
				files["outside.php"] = "custom"
			case "invalid version":
				files["wordpress/wp-includes/version.php"] = "HTML error page"
			}
			for path, data := range files {
				writer, err := zw.Create(path)
				if err != nil {
					t.Fatal(err)
				}
				_, _ = writer.Write([]byte(data))
			}
			if scenario == "symlink" {
				header := &zip.FileHeader{Name: "wordpress/wp-content/plugins/link"}
				header.SetMode(os.ModeSymlink | 0777)
				writer, _ := zw.CreateHeader(header)
				_, _ = writer.Write([]byte("/tmp/user-files"))
			}
			if err := zw.Close(); err != nil {
				t.Fatal(err)
			}
			data := buf.Bytes()
			if scenario == "html" {
				data = []byte("HTTP gateway error")
			}
			if err := os.WriteFile(name, data, 0600); err != nil {
				t.Fatal(err)
			}
			out, err := exec.Command(php, append(append([]string{}, flags...), "-r", body, name)...).CombinedOutput()
			if (err == nil) != (scenario == "valid") {
				t.Fatalf("error=%v output=%s", err, out)
			}
		})
	}
}

func TestInstallerWordPressReceiptMatchesPublishedBytesAndReplacesSymlink(t *testing.T) {
	php, _ := installerWordPressPHPRuntime(t, false)
	script := readInstallScript(t, installScriptPath)
	helper := extractShellFunction(t, script, "write_wordpress_origin_receipt", "verify_signed_release_asset")
	helper = strings.Replace(helper, `local php_cli="/usr/local/lsws/lsphp85/bin/php"`, "local php_cli="+strconv.Quote(filepath.ToSlash(php)), 1)
	for _, linked := range []bool{false, true} {
		t.Run(fmt.Sprint("receipt symlink=", linked), func(t *testing.T) {
			root := filepath.ToSlash(t.TempDir())
			archive := root + "/wordpress.zip"
			data := []byte("exact original downloaded bytes")
			if err := os.WriteFile(archive, data, 0600); err != nil {
				t.Fatal(err)
			}
			victim := root + "/user-file"
			if linked {
				if err := os.WriteFile(victim, []byte("preserve me"), 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(victim, archive+".origin.json"); err != nil {
					t.Skipf("symlink fixture unavailable: %v", err)
				}
			}
			out, err := lifecycleBash(t, helper+"\nwrite_wordpress_origin_receipt "+strconv.Quote(archive))
			if err != nil {
				t.Fatalf("%v: %s", err, out)
			}
			encoded, err := os.ReadFile(archive + ".origin.json")
			if err != nil {
				t.Fatal(err)
			}
			var receipt map[string]any
			if err := json.Unmarshal(encoded, &receipt); err != nil {
				t.Fatal(err)
			}
			sha := sha256.Sum256(data)
			if len(receipt) != 3 || receipt["source_url"] != "https://wordpress.org/latest.zip" || receipt["sha256"] != hex.EncodeToString(sha[:]) || receipt["archive_bytes"] != float64(len(data)) {
				t.Fatalf("incorrect receipt: %s", encoded)
			}
			info, err := os.Lstat(archive + ".origin.json")
			if err != nil || !info.Mode().IsRegular() || (runtime.GOOS != "windows" && info.Mode().Perm() != 0600) {
				t.Fatalf("unsafe receipt mode: %v, %v", info, err)
			}
			if linked {
				unchanged, _ := os.ReadFile(victim)
				if string(unchanged) != "preserve me" {
					t.Fatal("receipt write followed an existing symlink")
				}
			}
		})
	}
}

func TestInstallerWordPressSourceReceiptIsNeverInventedForRetainedCache(t *testing.T) {
	script := readInstallScript(t, installScriptPath)
	start := requiredIndex(t, script, "WP_ZIP=\"$INSTALL_DIR/packages/wordpress.zip\"")
	end := requiredIndex(t, script[start:], "# 生成面板安全凭证")
	block := script[start : start+end]
	repairEnd := requiredIndex(t, block, "\nelse\n")
	if strings.Contains(block[:repairEnd], "write_wordpress_origin_receipt") {
		t.Fatal("repair must never claim old/uploaded caches came from official download")
	}
	for _, required := range []string{`download_official_wordpress_archive "$WP_ZIP_TMP" && validate_installer_wordpress_archive "$WP_ZIP_TMP"`, `mv -fT -- "$WP_ZIP_TMP" "$WP_ZIP"`, `write_wordpress_origin_receipt "$WP_ZIP"`, `rm -f -- "${WP_ZIP}.origin.json"`} {
		if !strings.Contains(block, required) {
			t.Fatalf("cache publication missing %s", required)
		}
	}
	if strings.Index(block, `validate_installer_wordpress_archive`) > strings.Index(block, `write_wordpress_origin_receipt`) {
		t.Fatal("receipt must follow archive validation")
	}
}

func TestInstallerWordPressCachePublicationNeverMarksFailedOrRetainedDownloads(t *testing.T) {
	php, _ := installerWordPressPHPRuntime(t, false)
	script := readInstallScript(t, installScriptPath)
	start := requiredIndex(t, script, "WP_ZIP=\"$INSTALL_DIR/packages/wordpress.zip\"")
	end := requiredIndex(t, script[start:], "# 生成面板安全凭证")
	block := script[start : start+end]
	helpers := extractShellFunction(t, script, "file_size_within_limit", "download_file") + "\n" + extractShellFunction(t, script, "write_wordpress_origin_receipt", "verify_signed_release_asset")
	helpers = strings.Replace(helpers, `local php_cli="/usr/local/lsws/lsphp85/bin/php"`, "local php_cli="+strconv.Quote(filepath.ToSlash(php)), 1)
	for _, scenario := range []string{"official success", "repair old cache", "repair origin cache", "download failure", "validation failure", "receipt directory"} {
		t.Run(scenario, func(t *testing.T) {
			root := filepath.ToSlash(t.TempDir())
			for _, dir := range []string{root + "/install/packages", root + "/work"} {
				if err := os.MkdirAll(dir, 0700); err != nil {
					t.Fatal(err)
				}
			}
			archive := root + "/install/packages/wordpress.zip"
			repair := strings.HasPrefix(scenario, "repair")
			if repair {
				if err := os.WriteFile(archive, []byte("retained original cache"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if scenario == "repair origin cache" {
				if err := os.WriteFile(archive+".origin.json", []byte("keep exact original receipt"), 0600); err != nil {
					t.Fatal(err)
				}
			} else if scenario == "receipt directory" {
				if err := os.Mkdir(archive+".origin.json", 0700); err != nil {
					t.Fatal(err)
				}
			}
			fixture := fmt.Sprintf("INSTALL_DIR=%q\nINSTALL_WORKDIR=%q\nWORDPRESS_ZIP_MAX_BYTES=1024\nREPAIR_MODE=%t\nSCENARIO=%q\n", root+"/install", root+"/work", repair, scenario) + helpers + `
log_info() { :; }
log_warn() { :; }
sleep() { :; }
download_official_wordpress_archive() { [[ "$SCENARIO" != 'download failure' ]] || return 1; printf '%s' 'new official archive' > "$1"; }
validate_installer_wordpress_archive() { [[ "$SCENARIO" != 'validation failure' ]]; }
` + block + "\necho CACHE_FLOW_COMPLETE\n"
			out, err := lifecycleBash(t, fixture)
			if err != nil || !strings.Contains(string(out), "CACHE_FLOW_COMPLETE") {
				t.Fatalf("%v: %s", err, out)
			}
			actual, archiveErr := os.ReadFile(archive)
			receipt, receiptErr := os.ReadFile(archive + ".origin.json")
			switch scenario {
			case "official success":
				var metadata map[string]any
				if archiveErr != nil || string(actual) != "new official archive" || receiptErr != nil || json.Unmarshal(receipt, &metadata) != nil || metadata["source_url"] != "https://wordpress.org/latest.zip" {
					t.Fatalf("official cache not marked exactly: %s %s", actual, receipt)
				}
			case "repair old cache", "repair origin cache":
				if archiveErr != nil || string(actual) != "retained original cache" {
					t.Fatal("repair changed existing cache")
				}
				if scenario == "repair old cache" && !os.IsNotExist(receiptErr) {
					t.Fatal("repair invented official source metadata")
				}
				if scenario == "repair origin cache" && (receiptErr != nil || string(receipt) != "keep exact original receipt") {
					t.Fatal("repair changed source metadata")
				}
			case "receipt directory":
				if archiveErr != nil || string(actual) != "new official archive" || receiptErr == nil {
					t.Fatal("receipt failure must preserve deployable cache without an official receipt")
				}
				entries, _ := os.ReadDir(archive + ".origin.json")
				if len(entries) != 0 {
					t.Fatal("receipt publication wrote inside an unexpected directory")
				}
			default:
				if !os.IsNotExist(archiveErr) || !os.IsNotExist(receiptErr) {
					t.Fatal("failed download or validation left a cache or receipt")
				}
			}
			staged, _ := filepath.Glob(archive + ".origin.json.*")
			if len(staged) != 0 {
				t.Fatalf("receipt stage leaked: %v", staged)
			}
		})
	}
}
