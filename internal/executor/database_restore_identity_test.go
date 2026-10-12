package executor

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zangwp/OLS-WPanel/internal/config"
)

// A local process model checks the actual argument/stdin separation. It does
// not emulate server SQL authorization and is not a MariaDB isolation test.
func databaseImportTestAdmin(sql string) bool {
	fail := func() { fmt.Fprintln(os.Stderr, "injected identity administration failure"); os.Exit(1) }
	path := os.Getenv("OLS_IMPORT_TEST_STATE")
	if path == "" {
		path = os.Getenv("OLS_BACKUP_TEST_STATE") + ".identity"
	}
	if strings.HasPrefix(sql, "SELECT CONCAT(CURRENT_USER()") {
		if os.Getenv("OLS_IMPORT_TEST_AUTH_FAIL") == "1" {
			fail()
		}
		user := ""
		for index, arg := range os.Args {
			if arg == "-u" && index+1 < len(os.Args) {
				user = os.Args[index+1]
			}
		}
		fmt.Printf("%s@localhost\t0\n", user)
		return true
	}
	if strings.HasPrefix(sql, "CREATE USER ") {
		if os.Getenv("OLS_IMPORT_TEST_CREATE_FAIL") == "1" {
			fail()
		}
		if err := os.WriteFile(path, nil, 0600); err != nil {
			fail()
		}
		if os.Getenv("OLS_IMPORT_TEST_RECEIPT_FAIL") == "1" {
			user := strings.Split(sql, "'")[1]
			identity := databaseImportIdentity{Version: 1, Database: "site_db", User: user}
			receipt := filepath.Join(filepath.Dir(path), "database-import-identities", databaseImportReceiptName(identity))
			if err := os.WriteFile(receipt, []byte("collision fixture"), 0600); err != nil {
				fail()
			}
		}
		return true
	}
	if strings.HasPrefix(sql, "GRANT ") {
		if err := os.WriteFile(path, []byte(strings.TrimSpace(sql)), 0600); err != nil {
			fail()
		}
		return true
	}
	if strings.HasPrefix(sql, "SHOW GRANTS FOR ") {
		body, err := os.ReadFile(path)
		if err != nil {
			fail()
		}
		grant := strings.TrimSuffix(string(body), ";")
		account := strings.TrimPrefix(strings.TrimSuffix(strings.TrimSpace(sql), ";"), "SHOW GRANTS FOR ")
		fmt.Printf("GRANT USAGE ON *.* TO %s IDENTIFIED BY PASSWORD '*0123456789012345678901234567890123456789'\n%s\n", account, grant)
		if os.Getenv("OLS_IMPORT_TEST_GRANTS_FAIL") == "1" {
			fmt.Printf("GRANT ALL PRIVILEGES ON *.* TO %s WITH GRANT OPTION\n", account)
		}
		return true
	}
	if strings.HasPrefix(sql, "SELECT IF(") {
		if os.Getenv("OLS_IMPORT_TEST_ISOLATION_FAIL") == "1" {
			fmt.Println("DENIED")
		} else {
			fmt.Println("OK")
		}
		return true
	}
	if strings.HasPrefix(sql, "SELECT statement FROM ") {
		fmt.Println("DROP VIEW IF EXISTS `site_db`.`old_view`;\nDROP PROCEDURE IF EXISTS `site_db`.`old_routine`;\nDROP EVENT IF EXISTS `site_db`.`old_event`;\nDROP TABLE IF EXISTS `site_db`.`old_table`;")
		return true
	}
	if strings.HasPrefix(sql, "SET FOREIGN_KEY_CHECKS=0;") && strings.Contains(sql, "DROP TABLE IF EXISTS") {
		_ = os.WriteFile(path+".cleared", []byte(sql), 0600)
		return true
	}
	if strings.HasPrefix(sql, "ALTER USER ") {
		_ = os.WriteFile(path+".altered", []byte("yes"), 0600)
		if strings.Contains(sql, "ACCOUNT LOCK") && os.Getenv("OLS_IMPORT_TEST_LOCK_FAIL") == "1" {
			fail()
		}
		return true
	}
	if strings.HasPrefix(sql, "SELECT COUNT(*) FROM (") && strings.Contains(sql, "DEFINER") {
		if os.Getenv("OLS_IMPORT_TEST_RETAIN") == "1" {
			fmt.Println("1")
		} else {
			fmt.Println("0")
		}
		return true
	}
	if strings.HasPrefix(sql, "DROP USER ") {
		_ = os.WriteFile(path+".dropped", []byte("yes"), 0600)
		return true
	}
	return false
}

func TestDatabaseImportIdentityProcessHelper(t *testing.T) {
	if os.Getenv("OLS_IMPORT_TEST_HELPER") != "1" {
		return
	}
	args := os.Args
	for len(args) > 0 && args[0] != "--" {
		args = args[1:]
	}
	if len(args) < 2 {
		os.Exit(2)
	}
	input, err := io.ReadAll(os.Stdin)
	if err != nil {
		os.Exit(2)
	}
	user := ""
	for index, arg := range args {
		if arg == "-u" && index+1 < len(args) {
			user = args[index+1]
		}
	}
	if user == "root" {
		if !databaseImportTestAdmin(string(input)) {
			fmt.Fprintln(os.Stderr, "untrusted SQL reached administrative process")
			os.Exit(1)
		}
		os.Exit(0)
	}
	if databaseImportTestAdmin(string(input)) {
		os.Exit(0)
	}
	if !databaseImportUserPattern.MatchString(user) || args[1] != "--no-defaults" {
		os.Exit(3)
	}
	for _, required := range []string{"--batch", "--binary-mode", "--local-infile=0", "--skip-reconnect", "--protocol=SOCKET"} {
		found := false
		for _, arg := range args {
			if arg == required {
				found = true
			}
		}
		if !found {
			os.Exit(3)
		}
	}
	if os.Getenv("MYSQL_PWD") == "fixture-admin-password" || os.Getenv("MYSQL_PWD") == "" {
		os.Exit(3)
	}
	if err := os.WriteFile(os.Getenv("OLS_IMPORT_TEST_INPUT"), input, 0600); err != nil {
		os.Exit(2)
	}
	if os.Getenv("OLS_IMPORT_TEST_IMPORT_FAIL") == "1" {
		fmt.Fprintln(os.Stderr, "injected SQL rejection")
		os.Exit(1)
	}
	os.Exit(0)
}

func databaseImportProcessCommand(ctx context.Context, client string, args ...string) *exec.Cmd {
	return exec.CommandContext(ctx, os.Args[0], append([]string{"-test.run=^TestDatabaseImportIdentityProcessHelper$", "--"}, args...)...)
}

func setupDatabaseImportIdentityTest(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	old := config.AppConfig
	config.AppConfig = &config.Config{Panel: config.PanelConfig{DataDir: root, BackupDir: root}}
	t.Cleanup(func() { config.AppConfig = old })
	t.Setenv("OLS_IMPORT_TEST_HELPER", "1")
	t.Setenv("OLS_IMPORT_TEST_STATE", filepath.Join(root, "helper-state"))
	input := filepath.Join(root, "import.sql")
	t.Setenv("OLS_IMPORT_TEST_INPUT", input)
	return input
}

func TestDatabaseImportIdentityRestrictedProcessAndDefinerRetention(t *testing.T) {
	input := setupDatabaseImportIdentityTest(t)
	t.Setenv("OLS_IMPORT_TEST_RETAIN", "1")
	sql := "CREATE TABLE data (id int);\nUPDATE other_db.secret SET value=1;\nDROP TABLE other_db.secret;\nINSERT INTO other_db.secret VALUES (1);\nGRANT ALL ON *.* TO 'bad'@'localhost';\n\\! touch /tmp/unsafe\nsource /tmp/unsafe.sql\nCREATE DEFINER=`root`@`localhost` VIEW v AS SELECT 1;\n"
	result := importDatabaseSQL(context.Background(), databaseImportProcessCommand, "mysql", strings.NewReader(sql), "site_db", "fixture-admin-password", filterRestoreSQLBuffered)
	if !result.Success {
		t.Fatalf("result=%#v", result)
	}
	actual, err := os.ReadFile(input)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(actual), "UPDATE other_db.secret") || !strings.Contains(string(actual), "DEFINER=CURRENT_USER") || strings.Contains(string(actual), "DEFINER=`root`") {
		t.Fatalf("incorrect process input: %s", actual)
	}
	dir, err := databaseImportIdentityDirectory(false)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("retained identity receipts=%v error=%v", entries, err)
	}
	body, _ := os.ReadFile(filepath.Join(dir, entries[0].Name()))
	var receipt databaseImportIdentity
	if json.Unmarshal(body, &receipt) != nil || receipt.Database != "site_db" || !databaseImportUserPattern.MatchString(receipt.User) || strings.Contains(string(body), "password") {
		t.Fatalf("invalid ownership receipt: %s", body)
	}
}

func TestDatabaseImportIdentitySetupAndLockFailuresFailClosed(t *testing.T) {
	for _, scenario := range []struct {
		env      string
		imported bool
	}{{"OLS_IMPORT_TEST_CREATE_FAIL", false}, {"OLS_IMPORT_TEST_RECEIPT_FAIL", false}, {"OLS_IMPORT_TEST_GRANTS_FAIL", false}, {"OLS_IMPORT_TEST_ISOLATION_FAIL", false}, {"OLS_IMPORT_TEST_AUTH_FAIL", false}, {"OLS_IMPORT_TEST_LOCK_FAIL", true}, {"OLS_IMPORT_TEST_IMPORT_FAIL", true}} {
		t.Run(scenario.env, func(t *testing.T) {
			input := setupDatabaseImportIdentityTest(t)
			t.Setenv(scenario.env, "1")
			result := importDatabaseSQL(context.Background(), databaseImportProcessCommand, "mysql", strings.NewReader("CREATE TABLE data (id int);"), "site_db", "fixture-admin-password", filterRestoreSQLBuffered)
			if result.Success {
				t.Fatalf("failed setup/lock reported success: %#v", result)
			}
			_, err := os.Stat(input)
			if scenario.imported && err != nil || !scenario.imported && !os.IsNotExist(err) {
				t.Fatalf("imported=%v stat=%v result=%#v", scenario.imported, err, result)
			}
			if scenario.env == "OLS_IMPORT_TEST_CREATE_FAIL" {
				for _, suffix := range []string{".altered", ".dropped"} {
					if _, err := os.Stat(os.Getenv("OLS_IMPORT_TEST_STATE") + suffix); !os.IsNotExist(err) {
						t.Fatalf("unknown colliding identity was mutated: %v", err)
					}
				}
			}
			if scenario.env == "OLS_IMPORT_TEST_RECEIPT_FAIL" {
				if _, err := os.Stat(os.Getenv("OLS_IMPORT_TEST_STATE") + ".dropped"); err != nil {
					t.Fatal("newly created identity was not cleaned after receipt failure")
				}
			}
		})
	}
}

func TestDatabaseImportCleanupRequiresReceiptAndPreservesReferencedDefiners(t *testing.T) {
	setupDatabaseImportIdentityTest(t)
	identity, _, err := prepareDatabaseImportIdentity(context.Background(), databaseImportProcessCommand, "mysql", "site_db", "fixture-admin-password")
	if err != nil {
		t.Fatal(err)
	}
	dir, err := databaseImportIdentityDirectory(false)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, databaseImportReceiptName(identity))
	t.Setenv("OLS_IMPORT_TEST_RETAIN", "1")
	if err := finishDatabaseImportIdentity(databaseImportProcessCommand, "mysql", "fixture-admin-password", identity); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal("referenced restricted definer was removed")
	}
	if err := cleanupDatabaseImportIdentities(databaseImportProcessCommand, "mysql", "site_db", "fixture-admin-password", true); err == nil {
		t.Fatal("deleted schema cleanup ignored unexpected external definer")
	}
	t.Setenv("OLS_IMPORT_TEST_RETAIN", "0")
	if err := cleanupDatabaseImportIdentities(databaseImportProcessCommand, "mysql", "site_db", "fixture-admin-password", true); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("unreferenced owned identity receipt remained: %v", err)
	}
	if err := os.WriteFile(path, []byte(`{"version":1,"database":"site_db","user":"root"}`), 0600); err != nil {
		t.Fatal(err)
	}
	_ = os.Remove(os.Getenv("OLS_IMPORT_TEST_STATE") + ".dropped")
	if err := cleanupDatabaseImportIdentities(databaseImportProcessCommand, "mysql", "site_db", "fixture-admin-password", true); err == nil {
		t.Fatal("invalid ownership receipt allowed cleanup")
	}
	if _, err := os.Stat(os.Getenv("OLS_IMPORT_TEST_STATE") + ".dropped"); !os.IsNotExist(err) {
		t.Fatal("invalid ownership receipt caused an administrative DROP USER")
	}
}

func TestWPCoreDatabaseRestoreUsesIsolatedImporterAndClearsAllObjects(t *testing.T) {
	input := setupDatabaseImportIdentityTest(t)
	root := filepath.Dir(input)
	backup := filepath.Join(root, "update.sql.gz")
	file, err := os.OpenFile(backup, os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(file)
	_, _ = io.WriteString(gz, "CREATE TABLE data (id int);\nCREATE DEFINER=`root`@`localhost` VIEW new_view AS SELECT 1;\n")
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	old := wpCoreRestoreCommand
	wpCoreRestoreCommand = databaseImportProcessCommand
	t.Cleanup(func() { wpCoreRestoreCommand = old })
	t.Setenv("OLS_IMPORT_TEST_RETAIN", "1")
	if err := restoreWPCoreDatabase(context.Background(), filepath.Join(root, "mysql"), "site_db", "fixture-admin-password", backup); err != nil {
		t.Fatal(err)
	}
	cleared, err := os.ReadFile(os.Getenv("OLS_IMPORT_TEST_STATE") + ".cleared")
	if err != nil {
		t.Fatal(err)
	}
	for _, ddl := range []string{"DROP VIEW", "DROP PROCEDURE", "DROP EVENT", "DROP TABLE"} {
		if !strings.Contains(string(cleared), ddl) {
			t.Fatalf("old objects were not cleared: %s", cleared)
		}
	}
	body, err := os.ReadFile(input)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "DEFINER=CURRENT_USER") || strings.Contains(string(body), "DROP TABLE") {
		t.Fatalf("administrative DDL mixed into imported dump: %s", body)
	}
}

func TestDatabaseImportGrantsRequireExactSchemaAndNoExtraAuthority(t *testing.T) {
	identity := databaseImportIdentity{Version: 1, Database: "site_db", User: "olsri_0123456789abcdef01234567"}
	account := "`" + identity.User + "`@`localhost`"
	good := "GRANT USAGE ON *.* TO " + account + "\nGRANT " + databaseImportPrivileges + " ON `site\\_db`.* TO " + account
	if !databaseImportGrantsValid(good, identity) {
		t.Fatal("exact escaped schema rejected")
	}
	for _, bad := range []string{strings.ReplaceAll(good, "`site\\_db`", "`site_db`"), strings.ReplaceAll(good, "`site\\_db`", "`other_db`"), good + " WITH GRANT OPTION", good + "\nGRANT SELECT ON *.* TO " + account, good + "\nGRANT EXECUTE ON PROCEDURE other_db.p TO " + account, strings.ReplaceAll(good, "SELECT, INSERT", "FILE, INSERT"), good + "\nGRANT admin_role TO " + account, good + "\nGRANT ALL PRIVILEGES ON *.* TO PUBLIC"} {
		if databaseImportGrantsValid(bad, identity) {
			t.Fatalf("accepted excessive grants: %s", bad)
		}
	}
	if got := databaseImportGrantSchema("db_%"); got != "`db\\_\\%`" {
		t.Fatalf("literal wildcard escaping=%s", got)
	}
}

func TestDatabaseImportEnvironmentDropsInheritedClientCredentials(t *testing.T) {
	t.Setenv("MYSQL_PWD", "wrong")
	t.Setenv("MYSQL_HOST", "remote.example")
	t.Setenv("MYSQL_HOME", "/tmp/untrusted")
	t.Setenv("MARIADB_PWD", "other")
	env := databaseImportEnvironment("fixture")
	joined := strings.Join(env, "\n")
	if strings.Contains(joined, "MYSQL_HOST=") || strings.Contains(joined, "MYSQL_HOME=") || strings.Contains(joined, "MARIADB_PWD=") || strings.Count(joined, "MYSQL_PWD=") != 1 || !strings.Contains(joined, "MYSQL_PWD=fixture") {
		t.Fatalf("unexpected inherited client env: %s", joined)
	}
}

func TestDatabaseImportReceiptsRejectUnownedStorage(t *testing.T) {
	setupDatabaseImportIdentityTest(t)
	dir, err := databaseImportIdentityDirectory(true)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0777); err != nil {
		t.Fatal(err)
	}
	if _, err := databaseImportIdentityDirectory(true); err == nil {
		t.Fatal("accepted writable ownership directory")
	}
}

func TestDatabaseImportLockSerializesSameSchemaAndAllowsCancellation(t *testing.T) {
	ctx := context.Background()
	release, err := lockDatabaseImport(ctx, "lock_schema")
	if err != nil {
		t.Fatal(err)
	}
	other, err := lockDatabaseImport(ctx, "other_schema")
	if err != nil {
		release()
		t.Fatal(err)
	}
	other()
	waitCtx, cancel := context.WithCancel(ctx)
	cancel()
	if unlock, err := lockDatabaseImport(waitCtx, "lock_schema"); err == nil || unlock != nil {
		release()
		t.Fatal("canceled same-schema import acquired an active lock")
	}
	release()
	final, err := lockDatabaseImport(ctx, "lock_schema")
	if err != nil {
		t.Fatal(err)
	}
	final()
}
