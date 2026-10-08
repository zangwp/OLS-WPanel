package tests

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func lifecycleBash(t *testing.T, fixture string) ([]byte, error) {
	t.Helper()
	bash, err := exec.LookPath("bash")
	if err != nil {
		bash, err = exec.LookPath("sh")
		if err != nil {
			t.Skip("bash unavailable")
		}
		version, versionErr := exec.Command(bash, "--version").CombinedOutput()
		if versionErr != nil || !strings.Contains(string(version), "bash") {
			t.Skip("bash unavailable")
		}
	}
	return exec.Command(bash, "-c", "set -euo pipefail\n"+fixture).CombinedOutput()
}

func TestRepairVersionGuardRejectsDowngradeBeforeMutation(t *testing.T) {
	script := readUninstallSafetyScript(t)
	guard := extractShellFunction(t, script, "assert_repair_version_compatible", "assert_no_retained_sites")
	compare := extractShellFunction(t, script, "panel_version_at_least", "write_panel_service_unit")
	for _, tc := range []struct {
		current, target string
		allowed         bool
	}{
		{"v1.17.2", "v1.17.2", true},
		{"v1.17.2", "v1.18.0", true},
		{"v1.18.0", "v1.17.2", false},
		{"v1.17.10", "v1.17.2", false},
		{"", "v1.17.2", false},
		{"vbad", "v1.17.2", false},
	} {
		t.Run(tc.current+"-"+tc.target, func(t *testing.T) {
			fixture := fmt.Sprintf("INSTALLER_RELEASE_VERSION=%q\nmaintenance_current_version() { printf '%%s' %q; }\nlog_error() { echo ERROR; exit 1; }\n", tc.target, tc.current) + compare + "\n" + guard + "\nassert_repair_version_compatible\necho MUTATION\n"
			out, err := lifecycleBash(t, fixture)
			if (err == nil) != tc.allowed || strings.Contains(string(out), "MUTATION") != tc.allowed {
				t.Fatalf("allowed=%t err=%v output=%s", tc.allowed, err, out)
			}
		})
	}
	// Both CLI repair and the interactive menu must enter this same preflight.
	preflight := strings.Index(script, "if $REPAIR_MODE; then\n    prepare_panel_candidate")
	guardAt := strings.Index(script[preflight:], "\n    assert_repair_version_compatible\n")
	snapshotAt := strings.Index(script[preflight:], "\n    prepare_repair_snapshot\n")
	if guardAt < 0 || guardAt >= snapshotAt {
		t.Fatal("common repair preflight must reject downgrades before stopping/snapshotting")
	}
}

func TestReinstallRetainedSiteGuardBeforeDeletion(t *testing.T) {
	script := readUninstallSafetyScript(t)
	guard := extractShellFunction(t, script, "assert_no_retained_sites", "installed_maintenance_menu")
	for _, tc := range []struct {
		name, retained string
	}{
		{"empty", ""},
		{"website-files", "www/wwwroot/example/index.php"},
		{"runtime-config", "lsws/conf/ols-wpanel/sites-enabled/example.conf"},
		{"registry", "lsws/conf/ols-wpanel/sites.conf"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := filepath.ToSlash(t.TempDir())
			if tc.retained != "" {
				path := filepath.Join(root, tc.retained)
				if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte("virtualHost olsw_example {\n}\n"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			isolated := strings.NewReplacer("/www/", root+"/www/", "/usr/local/lsws/", root+"/lsws/").Replace(guard)
			fixture := fmt.Sprintf("CONFIG_FILE=%q\nDB_PATH=%q\nlog_error() { echo ERROR; exit 1; }\n", root+"/absent-config", root+"/absent-db") + isolated + "\nassert_no_retained_sites\necho DELETE_PANEL\n"
			out, err := lifecycleBash(t, fixture)
			allowed := tc.retained == ""
			if (err == nil) != allowed || strings.Contains(string(out), "DELETE_PANEL") != allowed {
				t.Fatalf("err=%v output=%s", err, out)
			}
			if tc.retained != "" {
				if _, err := os.Stat(filepath.Join(root, tc.retained)); err != nil {
					t.Fatal("retained site was changed", err)
				}
			}
		})
	}
	if !strings.Contains(script, "reinstall)\n            assert_no_retained_sites\n            confirm_ordinary_uninstall") || !strings.Contains(script, "else\n    assert_no_retained_sites\n    if [[ -e \"$SERVICE_PATH\" ]]") {
		t.Fatal("reinstall and fresh-install dispatch must check retained sites before mutation")
	}
}

func TestUninstallKeepsRepositoriesForRetainedRuntimes(t *testing.T) {
	script := readUninstallSafetyScript(t)
	restore := extractUninstallSafetyFunction(t, script, "restore_managed_apt_sources", "# ============================================================")
	remove := extractShellFunction(t, script, "remove_managed_source_file", "set_debian_source_meta")
	for _, policy := range []string{"retain-runtime", "retain-redis", "remove-runtime"} {
		t.Run(policy, func(t *testing.T) {
			root := filepath.ToSlash(t.TempDir())
			sources := root + "/etc/apt/sources.list.d"
			keys := root + "/usr/share/keyrings"
			for _, dir := range []string{sources, keys} {
				if err := os.MkdirAll(dir, 0700); err != nil {
					t.Fatal(err)
				}
			}
			for _, component := range []string{"debian", "ubuntu", "litespeed", "mariadb", "redis"} {
				if err := os.WriteFile(sources+"/ols-wpanel-"+component+".sources", []byte("# Managed by OLS WPanel\n"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			for _, key := range []string{"ols-wpanel-mariadb-archive-keyring.gpg", "ols-wpanel-redis-archive-keyring.asc"} {
				if err := os.WriteFile(keys+"/"+key, []byte("key"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			fixture := strings.NewReplacer("/etc/", root+"/etc/", "/usr/share/", root+"/usr/share/").Replace(remove+"\n"+restore) + "\nrestore_managed_apt_sources " + policy
			if out, err := lifecycleBash(t, fixture); err != nil {
				t.Fatalf("%v: %s", err, out)
			}
			for _, component := range []string{"litespeed", "mariadb", "redis"} {
				_, err := os.Stat(sources + "/ols-wpanel-" + component + ".sources")
				want := policy == "retain-runtime" || policy == "retain-redis" && component == "redis"
				if (err == nil) != want {
					t.Errorf("%s source exists=%t want=%t", component, err == nil, want)
				}
			}
			_, err := os.Stat(keys + "/ols-wpanel-redis-archive-keyring.asc")
			if (err == nil) != (policy != "remove-runtime") {
				t.Fatal("Redis source key retention mismatch")
			}
		})
	}
}

func installerPythonBlock(t *testing.T, marker string) string {
	t.Helper()
	script := readUninstallSafetyScript(t)
	markerStart := strings.Index(script, "<<'"+marker+"'")
	if markerStart < 0 {
		t.Fatal("missing embedded Python marker", marker)
	}
	start := strings.Index(script[markerStart:], "\nimport ")
	if start < 0 {
		t.Fatal("missing embedded Python block", marker)
	}
	start += markerStart
	end := strings.Index(script[start:], "\n"+marker+"\n")
	if end < 0 {
		t.Fatal("missing Python terminator", marker)
	}
	return script[start+1 : start+end]
}

func lifecyclePythonExecutable(t *testing.T) string {
	t.Helper()
	var python string
	for _, candidate := range []string{"python3", "python"} {
		if path, err := exec.LookPath(candidate); err == nil {
			if err := exec.Command(path, "--version").Run(); err == nil {
				python = path
				break
			}
		}
	}
	if python == "" {
		t.Skip("Python unavailable")
	}
	return python
}

func lifecyclePython(t *testing.T, code string, args ...string) ([]byte, error) {
	t.Helper()
	python := lifecyclePythonExecutable(t)
	return exec.Command(python, append([]string{"-X", "utf8", "-c", code}, args...)...).CombinedOutput()
}

func TestPurgeUsesProtectedConfiguredCredentials(t *testing.T) {
	root := filepath.ToSlash(t.TempDir())
	block := strings.NewReplacer("/www/", root+"/www/", "/usr/local/lsws/", root+"/lsws/").Replace(installerPythonBlock(t, "PYPURGEPREFLIGHT"))
	fixture := `import json,pathlib,sqlite3,subprocess,os,sys,stat
root=pathlib.Path(sys.argv[1]);work=root/'work';work.mkdir()
db=root/'panel.db'
with sqlite3.connect(db) as conn:conn.execute('CREATE TABLE websites(web_root TEXT,db_name TEXT)')
cfg={'panel':{'backup_dir':(root/'www/ols-wpanel/backups').as_posix()},'sqlite':{'path':str(db)},'mariadb':{'root_user':'customroot','root_password':'secret#value"with\\slash','socket':'/run/custom-mariadb.sock'}}
config=root/'config.json';config.write_text(json.dumps(cfg))
real_isfile=os.path.isfile
os.path.isfile=lambda p: p=='/usr/bin/mariadb' or real_isfile(p)
def database_call(args,**kwargs):
 assert args[1]=='--defaults-file='+str(work/'purge-mariadb.cnf'),args
 assert not any('secret' in arg for arg in args),args
 path=work/'purge-mariadb.cnf';text=path.read_text()
 assert 'user="customroot"' in text and 'socket="/run/custom-mariadb.sock"' in text,text
 assert 'password="secret#value\\"with\\\\slash"' in text,text
 if os.name!='nt':assert stat.S_IMODE(path.stat().st_mode)==0o600
 return subprocess.CompletedProcess(args,0,'mysql\nsys\ninformation_schema\nperformance_schema\n','')
subprocess.run=database_call
sys.argv=['fixture',str(config),str(work)]
` + "\n" + block
	if out, err := lifecyclePython(t, fixture, root); err != nil {
		t.Fatalf("purge authentication fixture: %v\n%s", err, out)
	}
}

func TestReinstallRejectsRegisteredSitesWithNoFiles(t *testing.T) {
	block := installerPythonBlock(t, "PYREINSTALLCHECK")
	for _, count := range []int{0, 1} {
		t.Run(strconv.Itoa(count), func(t *testing.T) {
			root := filepath.ToSlash(t.TempDir())
			fixture := `import pathlib,sqlite3,json,sys
root=pathlib.Path(sys.argv[1]);db=root/'panel.db';web=root/'www';web.mkdir()
with sqlite3.connect(db) as conn:
 conn.execute('CREATE TABLE websites(id INTEGER)')
 for i in range(int(sys.argv[2])):conn.execute('INSERT INTO websites VALUES (?)',(i,))
config=root/'config.json';config.write_text(json.dumps({'sqlite':{'path':str(db)},'paths':{'www_root':str(web)}}))
sys.argv=['fixture',str(config),str(db)]
` + "\n" + block
			out, err := lifecyclePython(t, fixture, root, strconv.Itoa(count))
			if (err == nil) != (count == 0) {
				t.Fatalf("count=%d err=%v output=%s", count, err, out)
			}
			if count > 0 && !strings.Contains(string(out), "检测到已登记网站") {
				t.Fatalf("unexpected guard failure: %s", out)
			}
		})
	}
}

func TestManualRecoveryPreservesCrashWALAndRestoresBackup(t *testing.T) {
	root := filepath.ToSlash(t.TempDir())
	// Leave a real committed WAL behind by exiting without closing SQLite.
	prepare := `import os,pathlib,sqlite3,sys
root=pathlib.Path(sys.argv[1]);panel=root/'www/ols-wpanel';panel.mkdir(parents=True)
backups=panel/'backups/panel-db';backups.mkdir(parents=True)
db=sqlite3.connect(panel/'panel.db');db.execute('PRAGMA journal_mode=WAL');db.execute('PRAGMA wal_autocheckpoint=0')
db.execute('CREATE TABLE websites(name TEXT)');db.execute("INSERT INTO websites VALUES ('backup')");db.commit()
backup=sqlite3.connect(backups/'fixture.db');db.backup(backup);backup.close()
db.execute("UPDATE websites SET name='crash-state'");db.commit()
os._exit(0)
`
	if out, err := lifecyclePython(t, prepare, root); err != nil {
		t.Fatalf("prepare crash: %v %s", err, out)
	}
	oldWAL, err := os.ReadFile(filepath.Join(root, "www/ols-wpanel/panel.db-wal"))
	if err != nil || len(oldWAL) == 0 {
		t.Fatal("fixture has no committed WAL", err)
	}
	doc, err := os.ReadFile("../docs/operations-and-recovery.md")
	if err != nil {
		t.Fatal(err)
	}
	text := string(doc)
	start := strings.Index(text, "   set -euo pipefail\n")
	if start < 0 {
		t.Fatal("missing recovery procedure")
	}
	end := strings.Index(text[start:], "   ```")
	if end < 0 {
		t.Fatal("missing recovery procedure terminator")
	}
	procedure := strings.ReplaceAll(text[start:start+end], "\n   ", "\n")
	procedure = strings.TrimPrefix(procedure, "   ")
	procedure = strings.NewReplacer("/www/", root+"/www/", "<backup-file>.db", "fixture.db").Replace(procedure)
	// Service operations are mocked; file moves run only under t.TempDir.
	python := "'" + strings.ReplaceAll(filepath.ToSlash(lifecyclePythonExecutable(t)), "'", "'\"'\"'") + "'"
	fixture := "python3() { " + python + " -X utf8 \"$@\"; }\nsystemctl() { case \"$1\" in show) echo 0;; is-active) return 3;; *) return 0;; esac; }\njournalctl() { :; }\n" +
		// Minimal Git-for-Windows omits install; its fixture fallback only copies
		// between temporary paths. Linux exercises the actual mode-setting tool.
		"if ! command -v install >/dev/null; then install() { test \"$1\" = -m && test \"$2\" = 0600 && test \"$3\" = -- || return 1; shift 3; cp -- \"$@\"; }; fi\n" + procedure
	if out, err := lifecycleBash(t, fixture); err != nil {
		t.Fatalf("recovery procedure: %v %s", err, out)
	}
	verify := `import pathlib,sqlite3,sys
panel=pathlib.Path(sys.argv[1])/'www/ols-wpanel'
with sqlite3.connect(panel/'panel.db') as db:assert db.execute('SELECT name FROM websites').fetchone()[0]=='backup'
saved=list(panel.glob('recovery.*'));assert len(saved)==1
assert (saved[0]/'panel.db').exists() and (saved[0]/'panel.db-wal').exists()
with sqlite3.connect(saved[0]/'panel.db') as db:assert db.execute('SELECT name FROM websites').fetchone()[0]=='crash-state'
`
	if out, err := lifecyclePython(t, verify, root); err != nil {
		t.Fatalf("verify recovery: %v %s", err, out)
	}
}
