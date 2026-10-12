package executor

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/zangwp/OLS-WPanel/internal/config"
	"github.com/zangwp/OLS-WPanel/internal/database"
)

func TestPanelDBRestoreRejectsAdmittedWorkBeforeSnapshotOrUnit(t *testing.T) {
	old := panelOperations
	panelOperations = &panelOperationLifecycle{}
	t.Cleanup(func() { panelOperations = old })
	q := &TaskQueue{queue: make(chan *Task, 1), tasks: make(map[string]*Task), lifecycle: panelOperations}
	if _, err := q.EnqueueContext(context.Background(), TaskRestoreBackup, nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = q.Shutdown(context.Background()) })
	root := t.TempDir()
	cfg := &config.Config{}
	cfg.Panel.BackupDir, cfg.Panel.DataDir = root, root
	if _, err := StartPanelDBRestore(cfg, "not-opened.sql"); !errors.Is(err, ErrPanelOperationsBusy) {
		t.Fatalf("restore did not reject existing task: %v", err)
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 0 {
		t.Fatalf("busy restore changed backup directory: %v / %v", entries, err)
	}
}

func TestPanelDBRestoreBarrierTransfersOnlyToStartedUnit(t *testing.T) {
	for _, fail := range []bool{true, false} {
		t.Run(map[bool]string{true: "unit failure reopens", false: "unit owns closed barrier"}[fail], func(t *testing.T) {
			root := t.TempDir()
			oldLifecycle, oldDB, oldCommand := panelOperations, database.DB, panelDBRestoreCommand
			panelOperations = &panelOperationLifecycle{}
			defer func() { panelOperations, database.DB, panelDBRestoreCommand = oldLifecycle, oldDB, oldCommand }()
			cfg := &config.Config{}
			cfg.Panel.BackupDir, cfg.Panel.DataDir = root, root
			cfg.SQLite.Path = filepath.Join(root, "panel.db")
			db, err := sql.Open("sqlite", cfg.SQLite.Path)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			if _, err = db.Exec(`CREATE TABLE proof(value TEXT); INSERT INTO proof VALUES('original')`); err != nil {
				t.Fatal(err)
			}
			database.DB = db
			program := "systemd-run"
			if runtime.GOOS == "windows" {
				program += ".exe"
			}
			if err = os.WriteFile(filepath.Join(root, program), []byte("lookup-only fixture"), 0700); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", root)
			calls := 0
			panelDBRestoreCommand = func(name string, args ...string) error {
				calls++
				if name != "systemd-run" {
					t.Fatalf("unexpected command %s", name)
				}
				if release, err := panelOperations.acquire(); !errors.Is(err, ErrPanelOperationsClosed) {
					if release != nil {
						release()
					}
					t.Fatalf("unit launched before admission closed: %v", err)
				}
				if fail {
					return errors.New("simulated unit failure")
				}
				return nil
			}
			_, err = StartPanelDBRestore(cfg, "selected.db")
			if fail != (err != nil) || calls != 1 {
				t.Fatalf("start result=%v calls=%d", err, calls)
			}
			release, gateErr := panelOperations.acquire()
			if fail {
				if gateErr != nil {
					t.Fatalf("failed launch left admission closed: %v", gateErr)
				}
				release()
			} else if !errors.Is(gateErr, ErrPanelOperationsClosed) {
				if release != nil {
					release()
				}
				t.Fatalf("started restore admitted a writer: %v", gateErr)
			}
		})
	}
}

func TestBusyAutoUpdatePreservesMaturityAndRetriesNextTick(t *testing.T) {
	root := t.TempDir()
	db, err := sql.Open("sqlite", filepath.Join(root, "auto.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	old := database.DB
	database.DB = db
	defer func() { database.DB = old }()
	if _, err = db.Exec(`CREATE TABLE security_settings(skey TEXT PRIMARY KEY,svalue TEXT,description TEXT,updated_at DATETIME DEFAULT CURRENT_TIMESTAMP); CREATE TABLE operation_logs(id INTEGER PRIMARY KEY,operation TEXT,target TEXT,status TEXT,message TEXT)`); err != nil {
		t.Fatal(err)
	}
	mature := time.Now().Add(-time.Hour).Format(time.RFC3339)
	setSecuritySetting("panel_auto_update_last_target_version", "v2.0.1")
	setSecuritySetting("panel_auto_update_last_attempt_at", mature)
	setSecuritySetting("panel_auto_update_last_check_at", time.Now().Format(time.RFC3339))
	recordPanelUpdateStage("auto", "v2.0.1", "busy", "skipped", ErrPanelOperationsBusy.Error())
	if got := readSecuritySetting("panel_auto_update_last_attempt_at"); got != mature {
		t.Fatalf("busy tick reset maturity: %s", got)
	}
	if got := readSecuritySetting("panel_auto_update_last_check_at"); got != "" {
		t.Fatalf("busy tick consumed check budget: %s", got)
	}
	if got := readSecuritySetting("panel_auto_update_last_stage"); got != "busy" {
		t.Fatalf("missing busy reason: %s", got)
	}
	settings := autoUpdateSettings{LastTargetVersion: "v2.0.1", LastAttemptAt: parseSettingTime("panel_auto_update_last_attempt_at"), LastCheckAt: parseSettingTime("panel_auto_update_last_check_at"), ReleaseDelay: 15 * time.Minute}
	if !shouldFetchForAutoUpdate(settings, time.Now()) {
		t.Fatal("busy tick prevented next scheduler retry")
	}
	if wait, waiting := shouldWaitForReleaseDelay(settings, "v2.0.1"); waiting {
		t.Fatalf("mature release restarted delay: %s", wait)
	}
}
