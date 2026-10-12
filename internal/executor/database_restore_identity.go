package executor

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/zangwp/OLS-WPanel/internal/config"
)

const databaseImportPrivileges = "SELECT, INSERT, UPDATE, DELETE, CREATE, DROP, INDEX, ALTER, REFERENCES, CREATE TEMPORARY TABLES, LOCK TABLES, CREATE VIEW, SHOW VIEW, CREATE ROUTINE, ALTER ROUTINE, EXECUTE, EVENT, TRIGGER"

var databaseImportUserPattern = regexp.MustCompile(`^olsri_[0-9a-f]{24}$`)
var databaseImportLocks sync.Map

func lockDatabaseImport(ctx context.Context, dbName string) (func(), error) {
	value, _ := databaseImportLocks.LoadOrStore(dbName, make(chan struct{}, 1))
	lock := value.(chan struct{})
	select {
	case lock <- struct{}{}:
		return func() { <-lock }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

type databaseImportIdentity struct {
	Version  int    `json:"version"`
	Database string `json:"database"`
	User     string `json:"user"`
}

type databaseImportCommand func(context.Context, string, ...string) *exec.Cmd

// A fresh account is used for every import. We never ALTER or REVOKE an
// existing account, even if its name resembles a panel import account. The
// private receipt is written only after CREATE USER succeeds. Locked accounts
// remain available as restricted DEFINER identities until their DB is deleted.
func prepareDatabaseImportIdentity(ctx context.Context, command databaseImportCommand, client, dbName, adminPassword string) (identity databaseImportIdentity, password string, err error) {
	if !databaseRestoreNameAllowed(dbName) || adminPassword == "" {
		return identity, "", errors.New("invalid database import identity")
	}
	dir, err := databaseImportIdentityDirectory(true)
	if err != nil {
		return identity, "", err
	}
	random := make([]byte, 36)
	if _, err := rand.Read(random); err != nil {
		return identity, "", errors.New("database import randomness unavailable")
	}
	identity = databaseImportIdentity{Version: 1, Database: dbName, User: "olsri_" + hex.EncodeToString(random[:12])}
	password = hex.EncodeToString(random[12:])
	account := "'" + identity.User + "'@'localhost'"
	if _, err := databaseImportAdmin(ctx, command, client, adminPassword, "CREATE USER "+account+" IDENTIFIED BY '"+password+"' ACCOUNT LOCK;"); err != nil {
		return identity, "", errors.New("cannot create isolated database import account")
	}
	// From here on only this account is known to have been created by us.
	receipt, _ := json.Marshal(identity)
	path := filepath.Join(dir, databaseImportReceiptName(identity))
	if err := writeDatabaseImportReceipt(path, receipt); err != nil {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_, cleanupErr := databaseImportAdmin(cleanupCtx, command, client, adminPassword, "DROP USER "+account+";")
		if cleanupErr != nil {
			return identity, "", errors.New("import ownership receipt failed; newly created account cleanup failed (account remains locked)")
		}
		return identity, "", errors.New("cannot persist database import ownership")
	}
	failure := func(cause error) (databaseImportIdentity, string, error) {
		// An interrupted UNLOCK may have reached the server. Lock again using
		// an independent deadline; never continue after uncertain setup.
		if lockErr := lockDatabaseImportIdentity(command, client, adminPassword, identity); lockErr != nil {
			return identity, "", errors.Join(cause, lockErr)
		}
		return identity, "", cause
	}
	schema := databaseImportGrantSchema(dbName)
	if _, err := databaseImportAdmin(ctx, command, client, adminPassword, "GRANT "+databaseImportPrivileges+" ON "+schema+".* TO "+account+";"); err != nil {
		return failure(errors.New("cannot grant isolated database import permissions"))
	}
	grants, err := databaseImportAdmin(ctx, command, client, adminPassword, "SHOW GRANTS FOR "+account+";")
	if err != nil || !databaseImportGrantsValid(string(grants), identity) {
		return failure(errors.New("database import grants could not be verified"))
	}
	// SHOW GRANTS alone does not reveal lower-level permissions on another
	// matching host account. Reject those, roles, proxies and global privilege
	// drift as well. Binary comparison avoids SQL string/wildcard ambiguity.
	schemaHex := hex.EncodeToString([]byte(strings.Trim(schema, "`")))
	query := fmt.Sprintf(`SELECT IF(
	 (SELECT COUNT(*) FROM mysql.global_priv WHERE User='%[1]s')=1 AND
	 (SELECT COUNT(*) FROM mysql.global_priv WHERE User='%[1]s' AND Host='localhost' AND COALESCE(JSON_VALUE(Priv,'$.access'),0)=0)=1 AND
	 (SELECT COUNT(*) FROM mysql.db WHERE User='%[1]s')=1 AND
	 (SELECT COUNT(*) FROM mysql.db WHERE User='%[1]s' AND Host='localhost' AND CAST(Db AS BINARY)=0x%[2]s)=1 AND
	 (SELECT COUNT(*) FROM mysql.tables_priv WHERE User='%[1]s')=0 AND
	 (SELECT COUNT(*) FROM mysql.columns_priv WHERE User='%[1]s')=0 AND
	 (SELECT COUNT(*) FROM mysql.procs_priv WHERE User='%[1]s')=0 AND
	 (SELECT COUNT(*) FROM mysql.roles_mapping WHERE User='%[1]s')=0 AND
	 (SELECT COUNT(*) FROM mysql.proxies_priv WHERE User='%[1]s')=0, 'OK', 'DENIED');`, identity.User, schemaHex)
	verified, err := databaseImportAdmin(ctx, command, client, adminPassword, query)
	if err != nil || strings.TrimSpace(string(verified)) != "OK" {
		return failure(errors.New("database import permission isolation could not be verified"))
	}
	if _, err := databaseImportAdmin(ctx, command, client, adminPassword, "ALTER USER "+account+" ACCOUNT UNLOCK;"); err != nil {
		return failure(errors.New("cannot unlock database import account"))
	}
	probe := command(ctx, client, databaseImportClientArgs(identity.User, "--raw", "--skip-column-names")...)
	probe.Env = databaseImportEnvironment(password)
	probe.Stdin = strings.NewReader("SELECT CONCAT(CURRENT_USER(),CHAR(9),@@skip_grant_tables);\n")
	probe.Stderr = io.Discard
	configureBackupCommandCancellation(probe)
	actual, probeErr := probe.Output()
	if probeErr != nil || strings.TrimSpace(string(actual)) != identity.User+"@localhost\t0" {
		return failure(errors.New("isolated database authentication could not be verified"))
	}
	return identity, password, nil
}

func databaseImportGrantSchema(dbName string) string {
	return "`" + strings.NewReplacer("\\", "\\\\", "_", "\\_", "%", "\\%", "`", "``").Replace(dbName) + "`"
}

func databaseImportGrantsValid(grants string, identity databaseImportIdentity) bool {
	if !databaseImportUserPattern.MatchString(identity.User) || !databaseRestoreNameAllowed(identity.Database) {
		return false
	}
	account := "`" + identity.User + "`@`localhost`"
	usagePrefix := "GRANT USAGE ON *.* TO " + account
	grantPrefix := "GRANT "
	grantSuffix := " ON " + databaseImportGrantSchema(identity.Database) + ".* TO " + account
	wanted := map[string]bool{}
	for _, privilege := range strings.Split(databaseImportPrivileges, ", ") {
		wanted[privilege] = true
	}
	usage, schema := false, false
	for _, line := range strings.Split(strings.TrimSpace(grants), "\n") {
		line = strings.TrimSpace(line)
		line = strings.ReplaceAll(line, "'"+identity.User+"'@'localhost'", account)
		if line == usagePrefix || strings.HasPrefix(line, usagePrefix+" IDENTIFIED BY PASSWORD '") && strings.HasSuffix(line, "'") && !strings.Contains(line, " WITH ") {
			if usage {
				return false
			}
			usage = true
			continue
		}
		if schema || !strings.HasPrefix(line, grantPrefix) || !strings.HasSuffix(line, grantSuffix) {
			return false
		}
		seen := map[string]bool{}
		for _, privilege := range strings.Split(strings.TrimSuffix(strings.TrimPrefix(line, grantPrefix), grantSuffix), ", ") {
			if !wanted[privilege] || seen[privilege] {
				return false
			}
			seen[privilege] = true
		}
		if len(seen) != len(wanted) {
			return false
		}
		schema = true
	}
	return usage && schema
}

func databaseImportClientArgs(user string, extra ...string) []string {
	args := []string{"--no-defaults", "--batch", "--binary-mode", "--local-infile=0", "--skip-reconnect", "--skip-auto-rehash", "--protocol=SOCKET", "--connect-timeout=10", "--default-character-set=utf8mb4", "-u", user}
	if config.AppConfig != nil && config.AppConfig.MariaDB.Socket != "" {
		args = append(args, "--socket="+config.AppConfig.MariaDB.Socket)
	}
	return append(args, extra...)
}

func databaseImportEnvironment(password string) []string {
	env := make([]string, 0, len(os.Environ())+1)
	for _, entry := range os.Environ() {
		name := strings.ToUpper(strings.SplitN(entry, "=", 2)[0])
		if strings.HasPrefix(name, "MYSQL_") || strings.HasPrefix(name, "MARIADB_") {
			continue
		}
		env = append(env, entry)
	}
	return append(env, "MYSQL_PWD="+password)
}

// Generated administrative SQL goes through stdin, never password-bearing
// argv. No input derived from an uploaded SQL body ever reaches this helper.
func databaseImportAdmin(ctx context.Context, command databaseImportCommand, client, password, sqlText string) ([]byte, error) {
	cmd := command(ctx, client, databaseImportClientArgs("root", "--raw", "--skip-column-names")...)
	cmd.Env = databaseImportEnvironment(password)
	cmd.Stdin = strings.NewReader(sqlText + "\n")
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = io.Discard // Failed CREATE/ALTER diagnostics may contain secrets.
	configureBackupCommandCancellation(cmd)
	if err := cmd.Run(); err != nil {
		return nil, errors.New("database administration failed")
	}
	return output.Bytes(), nil
}

func lockDatabaseImportIdentity(command databaseImportCommand, client, adminPassword string, identity databaseImportIdentity) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_, err := databaseImportAdmin(ctx, command, client, adminPassword, "ALTER USER '"+identity.User+"'@'localhost' ACCOUNT LOCK;")
	if err != nil {
		return errors.New("database import account could not be locked; restore is not confirmed")
	}
	return nil
}

func finishDatabaseImportIdentity(command databaseImportCommand, client, adminPassword string, identity databaseImportIdentity) error {
	if err := lockDatabaseImportIdentity(command, client, adminPassword, identity); err != nil {
		return err
	}
	return cleanupDatabaseImportIdentities(command, client, identity.Database, adminPassword, false)
}

func databaseImportIdentityDirectory(create bool) (string, error) {
	if config.AppConfig == nil {
		return "", errors.New("database import storage unavailable")
	}
	base := config.AppConfig.Panel.DataDir
	if base == "" {
		base = config.AppConfig.Panel.BackupDir
	}
	if !filepath.IsAbs(base) {
		return "", errors.New("invalid database import storage")
	}
	baseInfo, err := os.Lstat(base)
	if err != nil || !baseInfo.IsDir() || !databaseImportPrivateFile(baseInfo, false) {
		return "", errors.New("database import storage is not private")
	}
	for parent := filepath.Dir(base); ; parent = filepath.Dir(parent) {
		info, err := os.Lstat(parent)
		if err != nil {
			return "", errors.New("unsafe database import storage ancestor")
		}
		uid, _, known := wpInventoryFileOwner(info)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || !known || uid != os.Geteuid() && uid != 0 || info.Mode().Perm()&0022 != 0 && info.Mode()&os.ModeSticky == 0 {
			return "", errors.New("unsafe database import storage ancestor")
		}
		if filepath.Dir(parent) == parent {
			break
		}
	}
	dir := filepath.Join(base, "database-import-identities")
	if create {
		if err := os.Mkdir(dir, 0700); err != nil && !os.IsExist(err) {
			return "", err
		}
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return "", err
	}
	if !info.IsDir() || !databaseImportPrivateFile(info, true) {
		return "", errors.New("invalid database import ownership directory")
	}
	return dir, nil
}

func databaseImportPrivateFile(info os.FileInfo, private bool) bool {
	uid, _, known := wpInventoryFileOwner(info)
	if !known || uid != os.Geteuid() || info.Mode()&os.ModeSymlink != 0 {
		return false
	}
	if private {
		return info.Mode().Perm()&0077 == 0
	}
	return info.Mode().Perm()&0022 == 0
}

func databaseImportReceiptName(identity databaseImportIdentity) string {
	hash := sha256.Sum256([]byte(identity.Database))
	return hex.EncodeToString(hash[:]) + "-" + identity.User + ".json"
}

func writeDatabaseImportReceipt(path string, receipt []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, writeErr := f.Write(receipt)
	syncErr := f.Sync()
	closeErr := f.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil {
		_ = os.Remove(path)
		return errors.New("database import receipt write failed")
	}
	return nil
}

func removeDatabaseImportIdentities(dbName, adminPassword string) error {
	return cleanupDatabaseImportIdentities(databaseBackupCommand, "mysql", dbName, adminPassword, true)
}

func cleanupDatabaseImportIdentities(command databaseImportCommand, client, dbName, adminPassword string, deleted bool) error {
	if !databaseRestoreNameAllowed(dbName) {
		return errors.New("invalid import cleanup database")
	}
	dir, err := databaseImportIdentityDirectory(false)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	hash := sha256.Sum256([]byte(dbName))
	prefix := hex.EncodeToString(hash[:]) + "-"
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), prefix) {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || !databaseImportPrivateFile(info, true) || info.Size() > 1024 {
			return errors.New("invalid import ownership receipt")
		}
		body, err := os.ReadFile(path)
		var identity databaseImportIdentity
		if err != nil || json.Unmarshal(body, &identity) != nil || identity.Version != 1 || identity.Database != dbName || !databaseImportUserPattern.MatchString(identity.User) || entry.Name() != databaseImportReceiptName(identity) {
			return errors.New("invalid import ownership receipt")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		// Do not orphan an unexpected DEFINER in another schema, even for an
		// account whose creation receipt is ours.
		query := fmt.Sprintf("SELECT COUNT(*) FROM (SELECT TABLE_SCHEMA AS db, DEFINER FROM information_schema.VIEWS UNION ALL SELECT ROUTINE_SCHEMA, DEFINER FROM information_schema.ROUTINES UNION ALL SELECT TRIGGER_SCHEMA, DEFINER FROM information_schema.TRIGGERS UNION ALL SELECT EVENT_SCHEMA, DEFINER FROM information_schema.EVENTS) AS definitions WHERE DEFINER='%s@localhost'", identity.User)
		if deleted {
			query += fmt.Sprintf(" AND db<>'%s'", dbName)
		}
		query += ";"
		count, queryErr := databaseImportAdmin(ctx, command, client, adminPassword, query)
		value := strings.TrimSpace(string(count))
		if queryErr != nil || !regexp.MustCompile(`^(0|[1-9][0-9]*)$`).MatchString(value) {
			cancel()
			return errors.New("import identity references could not be verified")
		}
		if value != "0" {
			cancel()
			if deleted {
				return errors.New("import identity cleanup has unexpected external references")
			}
			continue
		}
		_, dropErr := databaseImportAdmin(ctx, command, client, adminPassword, "DROP USER IF EXISTS '"+identity.User+"'@'localhost';")
		cancel()
		if dropErr != nil {
			return dropErr
		}
		if err := os.Remove(path); err != nil {
			return err
		}
	}
	return nil
}
