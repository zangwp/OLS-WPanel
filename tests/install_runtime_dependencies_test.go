package tests

import (
	"strings"
	"testing"
)

func TestInstallerValidatesWebsiteRuntimeEvenWhenCLIModulesAreLoaded(t *testing.T) {
	script := readUninstallSafetyScript(t)
	helper := extractUninstallSafetyFunction(t, script, "validate_lsphp_wordpress_modules", "validate_mariadb_backup_commands() {")
	helper = strings.ReplaceAll(helper, "/usr/local/lsws/lsphp85/bin/php -m", "cli_modules")
	info := "phpinfo()\nPHP Version => 8.5.11\nServer API => LiteSpeed V8.1\nLoaded Configuration File => /usr/local/lsws/lsphp85/etc/php/8.5/litespeed/php.ini\nScan this dir for additional .ini files => /usr/local/lsws/lsphp85/etc/php/8.5/mods-available/\nConfiguration\nCore\nstandard\njson\nhash\nmysqli\ncurl\ndom\nexif\nfileinfo\nigbinary\nimagick\nintl\nmbstring\nopenssl\nxml\nzip\nredis\nZend OPcache\nPHP Variables\nPHP License\n"
	for _, tc := range []struct {
		name, info string
		ok         bool
	}{
		{"native modules", info, true},
		{"wrong scan directory", strings.ReplaceAll(info, "mods-available/", "litespeed/conf.d"), false},
		{"missing website mysqli", strings.ReplaceAll(info, "\nmysqli\n", "\n"), false},
		{"wrong SAPI", strings.ReplaceAll(info, "LiteSpeed V8.1", "Command Line Interface"), false},
		{"startup warning", info + "PHP Warning: Unable to load dynamic library\n", false},
		{"truncated probe", strings.ReplaceAll(info, "PHP License\n", ""), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture := `INSTALL_WORKDIR=$(mktemp -d)
trap 'rm -f "$INSTALL_WORKDIR/lsphp85-modules.txt" "$INSTALL_WORKDIR/lsphp85-lsapi-info.txt"; rmdir "$INSTALL_WORKDIR"' EXIT
PLATFORM_CODENAME=fixture PLATFORM_ARCH=fixture
log_error() { printf '%s\n' "$1" >&2; exit 61; }
cli_modules() { printf '%s\n' curl dom exif fileinfo gd imagick igbinary intl mbstring mysqli openssl pdo_mysql redis SimpleXML xml xmlreader xmlwriter zip 'Zend OPcache'; }
env() {
  test "$*" = '-i PATH=/usr/bin:/bin /usr/local/lsws/lsphp85/bin/lsphp -c /usr/local/lsws/lsphp85/etc/php/8.5/litespeed/php.ini -i' || return 1
  cat <<'FIXTURE_INFO'
` + tc.info + "FIXTURE_INFO\n}\n" + helper + "\nvalidate_lsphp_wordpress_modules\n"
			out, err := lifecycleBash(t, fixture)
			if (err == nil) != tc.ok || (!tc.ok && !strings.Contains(string(out), "LSPHP 8.5")) {
				t.Fatalf("ok=%t err=%v\n%s", tc.ok, err, out)
			}
		})
	}
}

func TestInstallerRequiresWorkingDatabaseBackupCommands(t *testing.T) {
	script := readUninstallSafetyScript(t)
	helper := extractUninstallSafetyFunction(t, script, "validate_mariadb_backup_commands", "configure_debian_source() {")
	for _, tc := range []struct {
		name, commands string
		ok             bool
	}{
		{"available", `mysql() { test "$1" = --version; }; mysqldump() { test "$1" = --version; }`, true},
		{"dump command missing", `mysql() { return 0; }; command() { test "$*" != '-v mysqldump'; }`, false},
		{"client fails", `mysql() { return 1; }; mysqldump() { return 0; }`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := lifecycleBash(t, "log_error() { printf '%s\\n' \"$1\" >&2; exit 61; }\n"+tc.commands+"\n"+helper+"\nvalidate_mariadb_backup_commands\n")
			if (err == nil) != tc.ok || (!tc.ok && !strings.Contains(string(out), "MariaDB 备份命令不可用")) {
				t.Fatalf("ok=%t err=%v\n%s", tc.ok, err, out)
			}
		})
	}
}
