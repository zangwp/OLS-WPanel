package executor

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func fixtureVPSCLIStorage() vpsCLIStorage {
	return vpsCLIStorage{
		ensureDirectory: func(path string, create bool) error {
			if create {
				return os.MkdirAll(path, 0700)
			}
			_, err := os.Stat(path)
			return err
		},
		readFile: func(path string, limit int64) ([]byte, error) {
			data, err := os.ReadFile(path)
			if err == nil && int64(len(data)) > limit {
				return nil, errors.New("fixture file too large")
			}
			return data, err
		},
		writeFile: func(path string, data []byte) error { return os.WriteFile(path, data, 0600) },
		lock:      func(string) (io.Closer, error) { return io.NopCloser(strings.NewReader("")), nil },
	}
}

func TestVPSCLIAuditNeverStoresTokensCredentialsOrUnvalidatedValues(t *testing.T) {
	secret := strings.Repeat("a", 48)
	for _, sample := range []struct{ action, value, message string }{
		{"ssh-port-confirm", secret, "confirmation token=" + secret},
		{"ssh-port-start", "2222:203.0.113.9", "bad nft comment token=" + secret},
		{"password", "administrator-password", "new password=administrator-password"},
		{"swap-custom", "secret:bad", "failure token=" + secret},
		{"dns-custom", "1.1.1.1, password", "password=administrator-password"},
	} {
		entry, err := normalizeVPSCLIAudit(sample.action, sample.value, "failed", sample.message)
		if err != nil {
			t.Fatal(err)
		}
		data, _ := json.Marshal(entry)
		for _, forbidden := range []string{secret, "administrator-password", "203.0.113.9", "secret:bad"} {
			if strings.Contains(string(data), forbidden) {
				t.Fatalf("secret leaked in %s", data)
			}
		}
	}
	entry, err := normalizeVPSCLIAudit("dns-custom", "1.1.1.1,2001:db8::1", "success", "saved")
	if err != nil || entry.Value != "1.1.1.1,2001:db8::1" {
		t.Fatalf("safe DNS values lost: %#v %v", entry, err)
	}
	entry, err = normalizeVPSCLIAudit("timezone", "Europe/London", "success", "saved")
	if err != nil || entry.Value != "Europe/London" {
		t.Fatal("validated IANA timezone lost")
	}
}

func TestVPSCLIHistoryIsBoundedAndNewestFirst(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "private")
	storage := fixtureVPSCLIStorage()
	for i := 0; i < vpsCLIHistoryLimit+5; i++ {
		entry, _ := normalizeVPSCLIAudit("clean", "", "success", strings.Repeat("x", 800))
		if err := appendVPSCLIHistoryWithStorage(dir, entry, storage); err != nil {
			t.Fatal(err)
		}
	}
	entries, err := readVPSCLIHistoryWithStorage(dir, storage)
	if err != nil || len(entries) != vpsCLIHistoryLimit {
		t.Fatalf("unbounded history: %d %v", len(entries), err)
	}
	if entries[0].At.Before(entries[len(entries)-1].At) || len([]rune(entries[0].Message)) > 300 {
		t.Fatal("incorrect order or unbounded message")
	}
	data, err := os.ReadFile(filepath.Join(dir, "history.jsonl"))
	if err != nil || len(data) > vpsCLIHistoryMaxBytes {
		t.Fatal("history file grew beyond limit")
	}
}

func TestVPSCLIHistoryDoesNotOverwriteInvalidOrUnreadableHistory(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "history.jsonl")
	if err := os.WriteFile(path, []byte("corrupt previous history"), 0600); err != nil {
		t.Fatal(err)
	}
	entry, _ := normalizeVPSCLIAudit("clean", "", "failed", "fixture failure")
	if err := appendVPSCLIHistoryWithStorage(dir, entry, fixtureVPSCLIStorage()); err == nil {
		t.Fatal("corrupt history was silently replaced")
	}
	data, _ := os.ReadFile(path)
	if string(data) != "corrupt previous history" {
		t.Fatal("prior evidence lost")
	}
	storage := fixtureVPSCLIStorage()
	storage.lock = func(string) (io.Closer, error) { return nil, errors.New("busy") }
	if err := appendVPSCLIHistoryWithStorage(dir, entry, storage); err == nil {
		t.Fatal("history proceeded without its cross-process lock")
	}
}

func TestVPSCLIHistoryByteBoundRetainsNewestUnicodeRecords(t *testing.T) {
	files := make(map[string][]byte)
	storage := fixtureVPSCLIStorage()
	storage.ensureDirectory = func(string, bool) error { return nil }
	storage.readFile = func(path string, limit int64) ([]byte, error) {
		data, ok := files[path]
		if !ok {
			return nil, os.ErrNotExist
		}
		return data, nil
	}
	storage.writeFile = func(path string, data []byte) error { files[path] = append([]byte(nil), data...); return nil }
	latest := ""
	for i := 0; i < vpsCLIHistoryLimit+5; i++ {
		latest = "host" + strings.Repeat("x", 240) + strconv.Itoa(i)
		entry, err := normalizeVPSCLIAudit("hostname", latest, "failed", strings.Repeat("𠮷", 300))
		if err != nil {
			t.Fatal(err)
		}
		if err := appendVPSCLIHistoryWithStorage("fixture", entry, storage); err != nil {
			t.Fatal("Unicode byte bound wedged the log:", err)
		}
	}
	entries, err := readVPSCLIHistoryWithStorage("fixture", storage)
	if err != nil || len(entries) == 0 || len(entries) >= vpsCLIHistoryLimit || entries[0].Value != latest {
		t.Fatalf("byte bound lost latest history: %d %v", len(entries), err)
	}
	if len(files[filepath.Join("fixture", "history.jsonl")]) > vpsCLIHistoryMaxBytes {
		t.Fatal("Unicode history exceeds byte bound")
	}
}
