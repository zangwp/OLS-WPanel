package executor

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/zangwp/OLS-WPanel/internal/config"
	"github.com/zangwp/OLS-WPanel/internal/database"
	"github.com/zangwp/OLS-WPanel/internal/models"
)

// No maintenance.php or sequential online dump is accepted as quiescence.
// This protocol only covers a dedicated panel UID and localhost DB account.
// External root/admin writers must be stopped by the administrator.
type siteBackupFreeze struct {
	site          *models.Website
	manifest      *models.SiteBackupManifest
	dir, password string
	cronLocks     io.Closer
	tables        siteBackupReadLocker
}

type siteBackupReadLocker interface {
	Alive() error
	Close() error
}

// Explicit operating-system/runtime boundaries are replaceable in unit tests;
// production uses the real OLS, MariaDB and Linux implementations below.
var (
	siteBackupSQL                = runSiteBackupSQL
	siteBackupValidateFilesystem = validateSiteBackupUserAndFilesystem
	siteBackupStopUser           = stopSiteBackupUserProcesses
	siteBackupUserStopped        = ensureSiteBackupUserStopped
	siteBackupVerifyTraffic      = verifySiteBackupMaintenance
	siteBackupMountReadOnly      = mountSiteBackupReadOnly
	siteBackupUnmountReadOnly    = unmountSiteBackupReadOnly
	siteBackupWriteVHost         = writeOLSFileAtomic
	siteBackupRestartOLS         = testAndRestartOpenLiteSpeed
	siteBackupLockTables         = func(ctx context.Context, site *models.Website, password string) (siteBackupReadLocker, error) {
		return lockSiteBackupTables(ctx, site, password)
	}
)

func databaseStatusForSite(ctx context.Context, id int, status *string) error {
	if database.GetDB() == nil {
		return errors.New("面板数据库不可用")
	}
	return database.GetDB().QueryRowContext(ctx, `SELECT status FROM websites WHERE id=?`, id).Scan(status)
}

func loadSiteBackupWebsite(ctx context.Context, db *sql.DB, id int) (*models.Website, error) {
	site, err := loadFileRestoreSite(ctx, db, id)
	if err != nil {
		return nil, err
	}
	err = db.QueryRowContext(ctx, `SELECT aliases,db_name,db_user,table_prefix,ols_vhost_config_path,ssl_enabled,ssl_cert_path,ssl_key_path FROM websites WHERE id=?`, id).Scan(&site.Aliases, &site.DBName, &site.DBUser, &site.TablePrefix, &site.OLSVHostConfigPath, &site.SSLEnabled, &site.SSLCertPath, &site.SSLKeyPath)
	return site, err
}

func validateSiteBackupWebsite(ctx context.Context, site *models.Website) error {
	if err := checkFileRestoreSite(ctx, database.GetDB(), site); err != nil {
		return err
	}
	if config.AppConfig == nil || !isValidMySQLIdentifier(site.DBName) || !isValidMySQLIdentifier(site.DBUser) || !IsValidWPTablePrefix(site.TablePrefix) || site.DBUser == "root" || !strings.HasPrefix(site.SystemUser, "wp_") {
		return errors.New("仅支持独占系统用户与本地数据库的受管 WordPress 网站")
	}
	if _, err := validateFileRestoreRoot(config.AppConfig.Paths.WWWRoot, site.WebRoot); err != nil {
		return err
	}
	var count int
	if err := database.GetDB().QueryRowContext(ctx, `SELECT COUNT(*) FROM websites WHERE system_user=? OR db_user=? OR db_name=? OR web_root=?`, site.SystemUser, site.DBUser, site.DBName, site.WebRoot).Scan(&count); err != nil || count != 1 {
		return errors.New("网站系统用户、数据库或目录并非独占")
	}
	_, err := normalizeOLSDomains(site.Domain, splitAliases(site.Aliases))
	return err
}

func acquireSiteBackupCronLocks(ctx context.Context, site *models.Website) (io.Closer, error) {
	rows, err := database.GetDB().QueryContext(ctx, `SELECT id FROM cron_jobs WHERE site_id=? OR run_as_user=? OR (task_type IN ('wp_cron','file_backup','wp_cli') AND command=?) ORDER BY id`, site.ID, site.SystemUser, site.Domain)
	if err != nil {
		return nil, err
	}
	var ids []int
	for rows.Next() {
		var id int
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	err = errors.Join(rows.Err(), rows.Close())
	if err != nil {
		return nil, err
	}
	return AcquireCronJobMutationLocks(ids)
}

func runSiteBackupSQL(ctx context.Context, password, query string) (string, error) {
	bounded, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(bounded, mariaDBClient(), databaseImportClientArgs("root", "--raw", "--skip-column-names", "-e", query)...)
	cmd.Env = databaseImportEnvironment(password)
	cmd.WaitDelay = time.Second
	output := newBoundedCronOutput(256 << 10)
	cmd.Stdout = output
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("数据库停写检查或操作失败（请检查本地 MariaDB 版本与权限）: %w", err)
	}
	return strings.TrimSpace(output.String()), nil
}

func validateSiteBackupDatabase(ctx context.Context, site *models.Website, password string) error {
	account, err := siteBackupSQL(ctx, password, fmt.Sprintf("SELECT CONCAT(Host,CHAR(9),COALESCE(JSON_UNQUOTE(JSON_EXTRACT(Priv,'$.account_locked')),'false')) FROM mysql.global_priv WHERE User='%s'", site.DBUser))
	if err != nil {
		return err
	}
	if account != "localhost\tfalse" && account != "localhost\t0" {
		return errors.New("站点数据库账户必须仅有 localhost 且原先未锁定；不自动修改既有锁定账户")
	}
	query := fmt.Sprintf(`SELECT
	 (SELECT COUNT(*) FROM information_schema.SCHEMA_PRIVILEGES WHERE TABLE_SCHEMA='%[1]s' AND GRANTEE NOT IN ("'%[2]s'@'localhost'","'root'@'localhost'"))+
	 (SELECT COUNT(*) FROM information_schema.TABLE_PRIVILEGES WHERE TABLE_SCHEMA='%[1]s' AND GRANTEE NOT IN ("'%[2]s'@'localhost'","'root'@'localhost'"))+
	 (SELECT COUNT(*) FROM information_schema.COLUMN_PRIVILEGES WHERE TABLE_SCHEMA='%[1]s' AND GRANTEE NOT IN ("'%[2]s'@'localhost'","'root'@'localhost'"))+
	 (SELECT COUNT(*) FROM information_schema.USER_PRIVILEGES WHERE PRIVILEGE_TYPE IN ('INSERT','UPDATE','DELETE','CREATE','DROP','ALTER','TRIGGER','EVENT','CREATE ROUTINE','ALTER ROUTINE','EXECUTE','FILE','SUPER','GRANT OPTION') AND GRANTEE NOT IN ("'root'@'localhost'","'mysql'@'localhost'"))+
	 (SELECT COUNT(*) FROM information_schema.VIEWS WHERE TABLE_SCHEMA='%[1]s')+
	 (SELECT COUNT(*) FROM information_schema.ROUTINES WHERE ROUTINE_SCHEMA='%[1]s')+
	 (SELECT COUNT(*) FROM information_schema.TRIGGERS WHERE TRIGGER_SCHEMA='%[1]s')+
	 (SELECT COUNT(*) FROM information_schema.EVENTS WHERE EVENT_SCHEMA='%[1]s')`, site.DBName, site.DBUser)
	value, err := siteBackupSQL(ctx, password, query)
	if err != nil {
		return err
	}
	if value != "0" {
		return errors.New("数据库存在共享权限、全局写账户或视图/例程/触发器/事件，首版无法安全冻结，未创建完整整站备份")
	}
	return nil
}

func renderSiteBackupMaintenance(site *models.Website, root, marker string) (string, error) {
	domains, err := normalizeOLSDomains(site.Domain, splitAliases(site.Aliases))
	if err != nil {
		return "", err
	}
	if _, err = validateOLSScalar("维护目录", root, true); err != nil {
		return "", err
	}
	if !validSiteBackupID(marker) {
		return "", errors.New("维护标记无效")
	}
	var out strings.Builder
	fmt.Fprintf(&out, "%s1\n%s%s\n%s%s\n%s%s\n", olsMetadataFormatPrefix, olsMetadataVHostPrefix, "olsw_"+buildSiteName(site.Domain), olsMetadataDomainsPrefix, strings.Join(domains, ","), olsMetadataRootPrefix, root)
	fmt.Fprintf(&out, "docRoot %s\nvhDomain %s\n", root, site.Domain)
	if len(domains) > 1 {
		fmt.Fprintf(&out, "vhAliases %s\n", strings.Join(domains[1:], ","))
	}
	out.WriteString("enableGzip 0\nindex {\n useServer 0\n indexFiles maintenance.html\n}\n")
	fmt.Fprintf(&out, "context / {\n type NULL\n location %s/\n allowBrowse 1\n extraHeaders <<<END_headers\nCache-Control: no-store\nX-OLS-WPanel-Backup: %s\nEND_headers\n}\n", root, marker)
	// Only an empty, root-owned static document root is mapped. No PHP handler,
	// .htaccess loading, proxy context or cache module from the live vhost survives.
	out.WriteString("rewrite {\n enable 1\n autoLoadHtaccess 0\n rules <<<END_rules\nRewriteRule ^ - [R=503,L]\nEND_rules\n}\n")
	if site.SSLEnabled {
		cert, err := validateOLSScalar("证书", site.SSLCertPath, true)
		if err != nil {
			return "", err
		}
		key, err := validateOLSScalar("私钥", site.SSLKeyPath, true)
		if err != nil {
			return "", err
		}
		fmt.Fprintf(&out, "vhssl {\n keyFile %s\n certFile %s\n certChain 1\n sslProtocol %d\n}\n", key, cert, olsTLSProtocols)
	}
	return out.String(), nil
}

func verifySiteBackupMaintenance(ctx context.Context, site *models.Website, marker string, maintenance bool) error {
	domains, err := normalizeOLSDomains(site.Domain, splitAliases(site.Aliases))
	if err != nil {
		return err
	}
	ips := []string{"127.0.0.1"}
	if olsIPv6Available() {
		ips = append(ips, "::1")
	}
	for _, ip := range ips {
		for _, domain := range domains {
			for _, scheme := range []string{"http", "https"} {
				if scheme == "https" && !site.SSLEnabled {
					continue
				}
				port := "80"
				if scheme == "https" {
					port = "443"
				}
				transport := &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "tcp", net.JoinHostPort(ip, port))
				}, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true}}
				client := &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
				paths := []string{"/", "/wp-login.php", "/wp-cron.php", "/wp-json/"}
				if !maintenance {
					paths = []string{"/"}
				}
				for _, path := range paths {
					method := http.MethodPost
					if !maintenance {
						method = http.MethodGet
					}
					req, err := http.NewRequestWithContext(ctx, method, scheme+"://"+domain+path, strings.NewReader("backup_probe=1"))
					if err != nil {
						transport.CloseIdleConnections()
						return err
					}
					resp, err := client.Do(req)
					if err != nil {
						transport.CloseIdleConnections()
						return fmt.Errorf("网站维护直连核验失败: %w", err)
					}
					_, readErr := io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
					resp.Body.Close()
					marked := resp.Header.Get("X-OLS-WPanel-Backup") == marker
					if readErr != nil || (maintenance && (resp.StatusCode != 503 || !marked || !strings.Contains(resp.Header.Get("Cache-Control"), "no-store"))) || (!maintenance && marked) {
						transport.CloseIdleConnections()
						return errors.New("网站未通过真实 503 停写/解除维护核验")
					}
				}
				transport.CloseIdleConnections()
			}
		}
	}
	return nil
}

func (f *siteBackupFreeze) save(phase string) error {
	next := *f.manifest
	next.Phase = phase
	if err := siteBackupPersistManifest(f.dir, &next); err != nil {
		return err
	}
	*f.manifest = next
	return nil
}

func beginSiteBackupFreeze(ctx context.Context, site *models.Website, manifest *models.SiteBackupManifest, dir, password string) (*siteBackupFreeze, error) {
	f := &siteBackupFreeze{site: site, manifest: manifest, dir: dir, password: password}
	locks, err := acquireSiteBackupCronLocks(ctx, site)
	if err != nil {
		return nil, fmt.Errorf("网站计划任务仍在运行或无法锁定: %w", err)
	}
	f.cronLocks = locks
	if err = siteBackupValidateFilesystem(ctx, site); err != nil {
		locks.Close()
		return nil, err
	}
	if err = validateSiteBackupDatabase(ctx, site, password); err != nil {
		locks.Close()
		return nil, err
	}
	path, err := managedSubpath(config.AppConfig.Paths.OLSVHostsAvailable, site.OLSVHostConfigPath, "站点 OLS 配置")
	if err != nil {
		locks.Close()
		return nil, err
	}
	enabled := olsVHostEnabledPath(config.AppConfig, path, site.Domain)
	target, err := os.Readlink(enabled)
	if err != nil || filepath.Clean(target) != path {
		locks.Close()
		return nil, errors.New("站点 OLS 启用配置不是预期的受管配置")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 1<<20 {
		locks.Close()
		return nil, errors.New("站点 OLS 配置身份不安全")
	}
	old, err := os.ReadFile(path)
	if err != nil {
		locks.Close()
		return nil, err
	}
	manifest.OriginalVHost = string(old)
	manifest.VHostPath = path
	manifest.Marker = uuid.NewString()
	maintenanceRoot, err := os.MkdirTemp(filepath.Dir(site.WebRoot), ".ols-wpanel-site-maintenance-")
	if err != nil {
		locks.Close()
		return nil, err
	}
	manifest.MaintenanceRoot = maintenanceRoot
	if err = os.Chmod(maintenanceRoot, 0755); err == nil {
		err = os.WriteFile(filepath.Join(maintenanceRoot, "maintenance.html"), []byte("Website backup maintenance. "+manifest.Marker), 0644)
	}
	content, renderErr := renderSiteBackupMaintenance(site, maintenanceRoot, manifest.Marker)
	if err = errors.Join(err, renderErr); err != nil {
		locks.Close()
		return nil, err
	}
	hash := sha256.Sum256([]byte(content))
	manifest.MaintenanceVHostSHA256 = hex.EncodeToString(hash[:])
	if err = f.save("freeze_intent"); err != nil {
		locks.Close()
		return nil, err
	}
	if err = writeSiteBackupMaintenanceOwner(site, manifest); err != nil {
		locks.Close()
		return nil, err
	}
	result, err := database.GetDB().ExecContext(ctx, `UPDATE websites SET status='backup_maintenance',updated_at=CURRENT_TIMESTAMP WHERE id=? AND status='active' AND domain=? AND web_root=? AND db_name=? AND db_user=?`, site.ID, site.Domain, site.WebRoot, site.DBName, site.DBUser)
	if err != nil {
		locks.Close()
		return nil, err
	}
	changed, _ := result.RowsAffected()
	if changed != 1 {
		locks.Close()
		return nil, errors.New("网站状态已变化，未进入维护")
	}
	// After the durable gate, any ambiguous failure retains an attention journal
	// and requires explicit recovery. Never reopen live traffic in a defer.
	if err = siteBackupWriteVHost(path, []byte(content), 0640); err == nil {
		_, err = siteBackupRestartOLS()
	}
	if err == nil {
		err = siteBackupVerifyTraffic(ctx, site, manifest.Marker, true)
	}
	if err == nil {
		err = f.save("traffic_blocked")
	}
	if err == nil {
		manifest.DBAccountLocked = true
		err = f.save("db_lock_intent")
	}
	if err == nil {
		_, err = siteBackupSQL(ctx, password, fmt.Sprintf("ALTER USER '%s'@'localhost' ACCOUNT LOCK", site.DBUser))
	}
	if err == nil {
		err = drainSiteBackupDatabase(ctx, site, password)
	}
	if err == nil {
		err = siteBackupStopUser(ctx, site)
	}
	if err == nil {
		err = f.save("frozen")
	}
	if err != nil {
		manifest.RequiresAttention = true
		manifest.Message = safeSiteBackupMessage(err)
		_ = f.save("freeze_failed")
		return f, err
	}
	return f, nil
}

func drainSiteBackupDatabase(ctx context.Context, site *models.Website, password string) error {
	rows, err := siteBackupSQL(ctx, password, fmt.Sprintf("SELECT ID,USER,COALESCE(DB,'') FROM information_schema.PROCESSLIST WHERE ID<>CONNECTION_ID() AND (USER='%s' OR DB='%s')", site.DBUser, site.DBName))
	if err != nil {
		return err
	}
	for _, row := range strings.Split(rows, "\n") {
		if row == "" {
			continue
		}
		fields := strings.Split(row, "\t")
		if len(fields) != 3 {
			return errors.New("数据库会话格式未知")
		}
		if fields[1] != site.DBUser {
			return errors.New("站点数据库仍有外部/root写入会话，请先停止后重试")
		}
		id, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil || id == 0 {
			return errors.New("数据库会话身份未知")
		}
		if _, err = siteBackupSQL(ctx, password, fmt.Sprintf("KILL CONNECTION %d", id)); err != nil {
			return err
		}
	}
	remaining, err := siteBackupSQL(ctx, password, fmt.Sprintf("SELECT COUNT(*) FROM information_schema.PROCESSLIST WHERE ID<>CONNECTION_ID() AND (USER='%s' OR DB='%s')", site.DBUser, site.DBName))
	if err != nil {
		return err
	}
	if remaining != "0" {
		return errors.New("数据库后台写入未停止")
	}
	return nil
}

// The mysql client remains alive with stdin open while holding selected READ
// locks. It cannot reconnect silently and lose them. A dead child aborts backup.
type siteBackupTableLocks struct {
	cmd   *exec.Cmd
	stdin io.WriteCloser
	done  chan error
}

func lockSiteBackupTables(ctx context.Context, site *models.Website, password string) (*siteBackupTableLocks, error) {
	output, err := siteBackupSQL(ctx, password, fmt.Sprintf("SELECT TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA='%s' AND TABLE_TYPE='BASE TABLE' ORDER BY TABLE_NAME", site.DBName))
	if err != nil {
		return nil, err
	}
	var tables []string
	for _, table := range strings.Split(output, "\n") {
		if !isValidMySQLIdentifier(table) {
			return nil, errors.New("数据库表名不受支持")
		}
		tables = append(tables, "`"+site.DBName+"`.`"+table+"` READ")
	}
	if len(tables) == 0 || len(tables) > 10000 {
		return nil, errors.New("数据库表集合为空或过多")
	}
	cmd := exec.CommandContext(ctx, mariaDBClient(), "--batch", "--raw", "--skip-column-names", "--unbuffered", "--skip-reconnect", "-u", "root")
	cmd.Env = append(os.Environ(), "MYSQL_PWD="+password)
	cmd.WaitDelay = time.Second
	cmd.Stderr = io.Discard
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		stdin.Close()
		return nil, err
	}
	if err = cmd.Start(); err != nil {
		stdin.Close()
		return nil, err
	}
	locks := &siteBackupTableLocks{cmd: cmd, stdin: stdin, done: make(chan error, 1)}
	ready := make(chan error, 1)
	marker := uuid.NewString()
	go func() {
		scanner := bufio.NewScanner(stdout)
		seen := false
		for scanner.Scan() {
			if scanner.Text() == marker && !seen {
				seen = true
				ready <- nil
			}
		}
		if !seen {
			ready <- errors.New("数据库 READ 锁未取得或连接提前退出")
		}
		locks.done <- cmd.Wait()
	}()
	if _, err = fmt.Fprintf(stdin, "SET SESSION lock_wait_timeout=15;\nLOCK TABLES %s;\nSELECT '%s';\n", strings.Join(tables, ","), marker); err != nil {
		locks.Close()
		return nil, err
	}
	timer := time.NewTimer(20 * time.Second)
	defer timer.Stop()
	select {
	case err = <-ready:
	case <-ctx.Done():
		err = ctx.Err()
	case <-timer.C:
		err = errors.New("等待数据库 READ 锁超时")
	}
	if err != nil {
		locks.Close()
		return nil, err
	}
	return locks, nil
}
func (l *siteBackupTableLocks) Alive() error {
	select {
	case err := <-l.done:
		l.done <- err
		return errors.New("数据库 READ 锁连接已退出，整站备份无效")
	default:
		return nil
	}
}
func (l *siteBackupTableLocks) Close() error {
	if l == nil {
		return nil
	}
	_ = l.stdin.Close()
	select {
	case err := <-l.done:
		return err
	case <-time.After(3 * time.Second):
		_ = l.cmd.Process.Kill()
		return <-l.done
	}
}

func (f *siteBackupFreeze) check(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	current, err := loadSiteBackupWebsite(ctx, database.GetDB(), f.site.ID)
	if err != nil {
		return err
	}
	if current.Status != models.StatusBackupMaintenance || current.Domain != f.site.Domain || current.Aliases != f.site.Aliases || current.WebRoot != f.site.WebRoot || current.DBName != f.site.DBName || current.DBUser != f.site.DBUser || current.TablePrefix != f.site.TablePrefix {
		return errors.New("维护期间网站绑定已变化，停止整站操作")
	}
	if err = siteBackupVerifyTraffic(ctx, f.site, f.manifest.Marker, true); err != nil {
		return err
	}
	if err = siteBackupUserStopped(ctx, f.site); err != nil {
		return err
	}
	if f.tables != nil {
		return f.tables.Alive()
	}
	return nil
}

func (f *siteBackupFreeze) readOnly(ctx context.Context) error {
	f.manifest.ReadOnlyMount = true
	if err := f.save("readonly_mount_intent"); err != nil {
		return err
	}
	id, err := siteBackupMountReadOnly(f.site.WebRoot)
	if err != nil {
		return err
	}
	f.manifest.MountID = id
	return f.save("frozen_readonly")
}

func (f *siteBackupFreeze) releaseReadOnly() error {
	if !f.manifest.ReadOnlyMount {
		return nil
	}
	if err := siteBackupUnmountReadOnly(f.site.WebRoot, f.manifest.MountID); err != nil {
		return err
	}
	f.manifest.ReadOnlyMount = false
	f.manifest.MountID = 0
	return f.save(f.manifest.Phase)
}

func (f *siteBackupFreeze) thaw(ctx context.Context) error {
	current, err := loadSiteBackupWebsite(ctx, database.GetDB(), f.site.ID)
	if err != nil {
		return err
	}
	if current.Status != models.StatusBackupMaintenance && current.Status != models.StatusActive {
		return errors.New("网站运行状态已被外部修改，不能自动解除维护")
	}
	if current.Domain != f.manifest.Domain || current.Aliases != f.manifest.Aliases || current.SystemUser != f.manifest.SystemUser || current.WebRoot != f.manifest.WebRoot || current.DBName != f.manifest.DBName || current.DBUser != f.manifest.DBUser || current.TablePrefix != f.manifest.TablePrefix || current.OLSVHostConfigPath != f.manifest.VHostPath {
		return errors.New("网站绑定已变化，不能自动解除维护")
	}
	if f.tables != nil {
		_ = f.tables.Close()
		f.tables = nil
	}
	if err := f.releaseReadOnly(); err != nil {
		return err
	}
	content, err := os.ReadFile(f.manifest.VHostPath)
	if err != nil {
		return err
	}
	hash := sha256.Sum256(content)
	if hex.EncodeToString(hash[:]) != f.manifest.MaintenanceVHostSHA256 && string(content) != f.manifest.OriginalVHost {
		return errors.New("维护 OLS 配置被外部修改，拒绝覆盖")
	}
	if f.manifest.DBAccountLocked {
		if _, err = siteBackupSQL(ctx, f.password, fmt.Sprintf("ALTER USER '%s'@'localhost' ACCOUNT UNLOCK", f.site.DBUser)); err != nil {
			return err
		}
	}
	if err = siteBackupWriteVHost(f.manifest.VHostPath, []byte(f.manifest.OriginalVHost), 0640); err == nil {
		_, err = siteBackupRestartOLS()
	}
	if err == nil {
		err = siteBackupVerifyTraffic(ctx, f.site, f.manifest.Marker, false)
	}
	if err == nil {
		var result sql.Result
		result, err = database.GetDB().ExecContext(ctx, `UPDATE websites SET status='active',updated_at=CURRENT_TIMESTAMP WHERE id=? AND status='backup_maintenance' AND domain=? AND web_root=? AND db_name=? AND db_user=?`, f.site.ID, f.site.Domain, f.site.WebRoot, f.site.DBName, f.site.DBUser)
		if err == nil {
			n, _ := result.RowsAffected()
			if n != 1 {
				err = errors.New("解除维护时网站绑定变化")
			}
		}
	}
	if err != nil {
		// Keep ordinary resume disabled. Restore both gates rather than allowing
		// a half-thawed site to accept writes after an operational failure.
		// A failure can occur before the initial freeze ever locked the account.
		// Persist ownership of this new re-lock before changing MariaDB so a
		// later explicit recovery will also unlock it.
		f.manifest.RequiresAttention = true
		f.manifest.DBAccountLocked = true
		intentErr := f.save(f.manifest.Phase)
		cleanup, stop := context.WithTimeout(context.Background(), 90*time.Second)
		defer stop()
		var lockErr error
		if intentErr == nil {
			_, lockErr = siteBackupSQL(cleanup, f.password, fmt.Sprintf("ALTER USER '%s'@'localhost' ACCOUNT LOCK", f.site.DBUser))
			if lockErr == nil {
				lockErr = drainSiteBackupDatabase(cleanup, f.site, f.password)
			}
			if lockErr == nil {
				lockErr = siteBackupStopUser(cleanup, f.site)
			}
		}
		maintenance, renderErr := renderSiteBackupMaintenance(f.site, f.manifest.MaintenanceRoot, f.manifest.Marker)
		writeErr := renderErr
		if writeErr == nil {
			writeErr = siteBackupWriteVHost(f.manifest.VHostPath, []byte(maintenance), 0640)
		}
		if writeErr == nil {
			_, writeErr = siteBackupRestartOLS()
		}
		if writeErr == nil {
			writeErr = siteBackupVerifyTraffic(cleanup, f.site, f.manifest.Marker, true)
		}
		f.manifest.RequiresAttention = true
		return errors.Join(err, intentErr, lockErr, writeErr)
	}
	f.manifest.DBAccountLocked = false
	f.manifest.RequiresAttention = false
	return nil
}

func (f *siteBackupFreeze) close() {
	if f.tables != nil {
		_ = f.tables.Close()
		f.tables = nil
	}
	if f.cronLocks != nil {
		_ = f.cronLocks.Close()
	}
}
