package executor

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/zangwp/OLS-WPanel/internal/database"
)

func securitySettingsLockTestDB(t *testing.T) (*sql.DB, string) {
	t.Helper()
	path := filepath.Join(privateSecurityTestDirectory(t), "security.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Ping(); err != nil {
		db.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db, path
}

func TestSecuritySettingsLockProcessHelper(t *testing.T) {
	path := os.Getenv("OLS_SECURITY_LOCK_TEST_DATABASE")
	if path == "" {
		t.Skip("runs only in the kernel-lock subprocess")
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	previous := database.DB
	database.DB = db
	defer func() { database.DB = previous }()
	mode := os.Getenv("OLS_SECURITY_LOCK_TEST_MODE")
	err = WithFail2banSettingsLock(func(func() error) error {
		if mode == "busy" {
			t.Fatal("a second process entered the locked operation")
		}
		if mode == "hold" {
			if err := os.WriteFile(path+".ready", []byte("locked"), 0600); err != nil {
				t.Fatal(err)
			}
			var one [1]byte
			_, _ = os.Stdin.Read(one[:])
		}
		return nil
	})
	if mode == "busy" {
		if !errors.Is(err, ErrSecuritySettingsBusy) {
			t.Fatalf("contention did not report busy: %v", err)
		}
	} else if err != nil {
		t.Fatal(err)
	}
}

func securityLockProcess(ctx context.Context, path, mode string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestSecuritySettingsLockProcessHelper$", "-test.count=1")
	cmd.Env = append(os.Environ(), "OLS_SECURITY_LOCK_TEST_DATABASE="+path, "OLS_SECURITY_LOCK_TEST_MODE="+mode)
	return cmd
}

func TestSecuritySettingsLockSerializesActualProcessesAndReleases(t *testing.T) {
	db, path := securitySettingsLockTestDB(t)
	release, err := acquireSecuritySettingsProcessLock(db)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if output, err := securityLockProcess(ctx, path, "busy").CombinedOutput(); err != nil {
		t.Fatalf("second process did not respect the first lock: %v %s", err, output)
	}
	if err := release(); err != nil {
		t.Fatal(err)
	}
	if output, err := securityLockProcess(ctx, path, "acquire").CombinedOutput(); err != nil {
		t.Fatalf("second process could not acquire a released lock: %v %s", err, output)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(path), ".ols-wpanel-security-settings.lock")); err != nil {
		t.Fatal("release removed the coordination inode", err)
	}
}

func TestSecuritySettingsLockIsReleasedWhenProcessDies(t *testing.T) {
	db, path := securitySettingsLockTestDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := securityLockProcess(ctx, path, "hold")
	output, err := os.CreateTemp(t.TempDir(), "child-output-*.log")
	if err != nil {
		t.Fatal(err)
	}
	defer output.Close()
	cmd.Stdout, cmd.Stderr = output, output
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer stdin.Close()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	processDone := make(chan error, 1)
	go func() { processDone <- cmd.Wait() }()
	defer func() { _ = cmd.Process.Kill() }()
	childOutput := func() string {
		data, _ := os.ReadFile(output.Name())
		return string(data)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(path + ".ready"); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("child process never acquired the lock: %s", childOutput())
		}
		select {
		case err := <-processDone:
			t.Fatalf("child process exited before acquiring the lock: %v %s", err, childOutput())
		case <-time.After(10 * time.Millisecond):
		}
	}
	if release, err := acquireSecuritySettingsProcessLock(db); !errors.Is(err, ErrSecuritySettingsBusy) {
		if release != nil {
			release()
		}
		t.Fatalf("parent did not see the child lock: %v", err)
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	<-processDone
	release, err := acquireSecuritySettingsProcessLock(db)
	if err != nil {
		t.Fatal("dead process left a stale lock", err)
	}
	if err := release(); err != nil {
		t.Fatal(err)
	}
}

func TestSecuritySettingsLockRejectsUnsafeFilesystem(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux ownership and no-follow checks")
	}
	for _, state := range []string{"symlink-file", "hardlink", "public-file", "public-directory", "symlink-directory"} {
		t.Run(state, func(t *testing.T) {
			directory := privateSecurityTestDirectory(t)
			path := filepath.Join(directory, ".ols-wpanel-security-settings.lock")
			other := filepath.Join(directory, "other")
			if err := os.WriteFile(other, []byte("unchanged"), 0600); err != nil {
				t.Fatal(err)
			}
			switch state {
			case "symlink-file":
				if err := os.Symlink(other, path); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(other, path); err != nil {
					t.Fatal(err)
				}
			case "public-file":
				if err := os.WriteFile(path, nil, 0644); err != nil {
					t.Fatal(err)
				}
			case "public-directory":
				if err := os.Chmod(directory, 0755); err != nil {
					t.Fatal(err)
				}
			case "symlink-directory":
				alias := filepath.Join(t.TempDir(), "alias")
				if err := os.Symlink(directory, alias); err != nil {
					t.Fatal(err)
				}
				path = filepath.Join(alias, ".ols-wpanel-security-settings.lock")
			}
			file, err := openSecuritySettingsLock(path)
			if err == nil {
				file.Close()
				t.Fatal("unsafe lock identity was accepted", state)
			}
			data, err := os.ReadFile(other)
			if err != nil || string(data) != "unchanged" {
				t.Fatal("rejected lock changed another file", err)
			}
		})
	}
}

func TestSecuritySettingsLockRejectsMissingOrMemoryDatabase(t *testing.T) {
	if _, err := securitySettingsLockPath(nil); err == nil {
		t.Fatal("nil database accepted")
	}
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := securitySettingsLockPath(db); err == nil {
		t.Fatal("in-memory database cannot coordinate another process")
	}
}
