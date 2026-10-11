package executor

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const siteBackupStreamTestSQL = "CREATE TABLE snapshot (id int);\nINSERT INTO snapshot VALUES (7);\n"

// Model the mysqldump/mysql process boundary while exercising the production
// compression, pipe and restore paths. No running MariaDB daemon is required.
func TestSiteBackupStreamProcessHelper(t *testing.T) {
	if os.Getenv("OLS_SITE_BACKUP_STREAM_HELPER") != "1" {
		return
	}
	args := os.Args
	for len(args) > 0 && args[0] != "--" {
		args = args[1:]
	}
	if len(args) < 2 {
		os.Exit(2)
	}
	switch args[1] {
	case "mysqldump":
		switch os.Getenv("OLS_SITE_BACKUP_STREAM_MODE") {
		case "fail":
			_, _ = io.WriteString(os.Stdout, siteBackupStreamTestSQL)
			_, _ = io.WriteString(os.Stderr, "injected dump failure")
			os.Exit(1)
		case "wait":
			for {
				time.Sleep(time.Second)
			}
		}
		_, _ = io.WriteString(os.Stdout, siteBackupStreamTestSQL)
	case "mysql":
		input, err := io.ReadAll(os.Stdin)
		want := "SET FOREIGN_KEY_CHECKS=0;\n" + siteBackupStreamTestSQL + "\nSET FOREIGN_KEY_CHECKS=1;\n"
		if err != nil || string(input) != want {
			_, _ = fmt.Fprintln(os.Stderr, "restore input was not the original SQL")
			os.Exit(1)
		}
	default:
		os.Exit(2)
	}
	os.Exit(0)
}

func useSiteBackupStreamTestCommand(t *testing.T) {
	t.Helper()
	t.Setenv("OLS_SITE_BACKUP_STREAM_HELPER", "1")
	oldCommand := databaseBackupCommand
	databaseBackupCommand = func(ctx context.Context, command string, args ...string) *exec.Cmd {
		childArgs := append([]string{"-test.run=^TestSiteBackupStreamProcessHelper$", "--", command}, args...)
		return exec.CommandContext(ctx, os.Args[0], childArgs...)
	}
	t.Cleanup(func() { databaseBackupCommand = oldCommand })
}

func TestSiteBackupDatabaseStreamRoundTrip(t *testing.T) {
	useSiteBackupStreamTestCommand(t)
	path := filepath.Join(t.TempDir(), "database.sql.gz")
	if err := dumpSiteBackupDatabase(context.Background(), "site_db", "test-not-secret", path); err != nil {
		t.Fatal(err)
	}
	compressed, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	gz, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		t.Fatal(err)
	}
	sql, readErr := io.ReadAll(gz)
	closeErr := gz.Close()
	if readErr != nil || closeErr != nil {
		t.Fatalf("read gzip: %v; close gzip: %v", readErr, closeErr)
	}
	if string(sql) != siteBackupStreamTestSQL {
		t.Fatalf("one gzip decode did not produce the original SQL: %q", sql)
	}
	// A structurally valid gzip alone is insufficient. Feed the artifact through
	// the real single-decode import path and assert what the mysql process gets.
	result := restoreDatabaseSnapshot(path, "site_db", "test-not-secret")
	if !result.Success {
		t.Fatalf("restore of generated backup failed: %#v", result)
	}
}

func TestSiteBackupDatabaseStreamRemovesFailedArtifact(t *testing.T) {
	useSiteBackupStreamTestCommand(t)
	t.Setenv("OLS_SITE_BACKUP_STREAM_MODE", "fail")
	path := filepath.Join(t.TempDir(), "database.sql.gz")
	err := dumpSiteBackupDatabase(context.Background(), "site_db", "test-not-secret", path)
	if err == nil || !strings.Contains(err.Error(), "injected dump failure") {
		t.Fatalf("error = %v, want subprocess failure", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("partial artifact remained: %v", err)
	}
}

func TestSiteBackupDatabaseStreamHonorsCancellation(t *testing.T) {
	useSiteBackupStreamTestCommand(t)
	t.Setenv("OLS_SITE_BACKUP_STREAM_MODE", "wait")
	path := filepath.Join(t.TempDir(), "database.sql.gz")
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	started := time.Now()
	if err := dumpSiteBackupDatabase(ctx, "site_db", "test-not-secret", path); err == nil {
		t.Fatal("cancelled dump succeeded")
	}
	if elapsed := time.Since(started); elapsed > 5*time.Second {
		t.Fatalf("cancelled dump did not stop promptly: %v", elapsed)
	}
	if ctx.Err() != context.DeadlineExceeded {
		t.Fatalf("context error = %v", ctx.Err())
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("cancelled artifact remained: %v", err)
	}
}
