package executor

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/zangwp/OLS-WPanel/internal/config"
)

const (
	olsMetadataFormatPrefix  = "# OLS-WPanel-Format: "
	olsMetadataVHostPrefix   = "# OLS-WPanel-VHost: "
	olsMetadataDomainsPrefix = "# OLS-WPanel-Domains: "
	olsMetadataRootPrefix    = "# OLS-WPanel-VHRoot: "
	olsDefaultVHostName      = "olsw_default"
	AliasRedirectServe       = "serve"
	AliasRedirectPermanent   = "301"
	AliasRedirectTemporary   = "302"
)

var (
	olsSafeNamePattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	olsSafeUserPattern = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
	runOLSCommand      = func(name string, args ...string) ([]byte, error) {
		return exec.Command(name, args...).CombinedOutput()
	}
	lookupOLSDefaultVHostUser = user.Lookup
	chownOLSDefaultVHostRoot  = os.Chown
)

type olsRuntimePaths struct {
	root         string
	mainConfig   string
	managed      string
	binary       string
	lsphp        string
	lsphpCLI     string
	listenerCert string
	listenerKey  string
}

type olsVHostMetadata struct {
	name       string
	domains    []string
	vhRoot     string
	configFile string
}

func currentOLSRuntimePaths() olsRuntimePaths {
	paths := olsRuntimePaths{
		root:         "/usr/local/lsws",
		mainConfig:   "/usr/local/lsws/conf/httpd_config.conf",
		managed:      "/usr/local/lsws/conf/ols-wpanel/sites.conf",
		binary:       "/usr/local/lsws/bin/openlitespeed",
		lsphp:        "/usr/local/lsws/lsphp85/bin/lsphp",
		lsphpCLI:     "/usr/local/lsws/lsphp85/bin/php",
		listenerCert: "/usr/local/lsws/conf/ols-wpanel/default.crt",
		listenerKey:  "/usr/local/lsws/conf/ols-wpanel/default.key",
	}
	if config.AppConfig == nil {
		return paths
	}
	cfg := config.AppConfig.Paths
	if strings.TrimSpace(cfg.OLSRoot) != "" {
		paths.root = filepath.Clean(cfg.OLSRoot)
	}
	if strings.TrimSpace(cfg.OLSMainConfig) != "" {
		paths.mainConfig = filepath.Clean(cfg.OLSMainConfig)
	}
	if strings.TrimSpace(cfg.OLSManagedConfig) != "" {
		paths.managed = filepath.Clean(cfg.OLSManagedConfig)
	}
	if strings.TrimSpace(cfg.OLSBinary) != "" {
		paths.binary = filepath.Clean(cfg.OLSBinary)
	}
	if strings.TrimSpace(cfg.LSPHPBinary) != "" {
		paths.lsphp = filepath.Clean(cfg.LSPHPBinary)
	}
	if strings.TrimSpace(cfg.LSPHPCLI) != "" {
		paths.lsphpCLI = filepath.Clean(cfg.LSPHPCLI)
	}
	if strings.TrimSpace(cfg.OLSListenerCert) != "" {
		paths.listenerCert = filepath.Clean(cfg.OLSListenerCert)
	}
	if strings.TrimSpace(cfg.OLSListenerKey) != "" {
		paths.listenerKey = filepath.Clean(cfg.OLSListenerKey)
	}
	return paths
}

// LSPHPBinaryPath exposes the configured PHP CLI built with the same LSPHP
// version and modules as the OpenLiteSpeed worker runtime.
func LSPHPBinaryPath() string { return currentOLSRuntimePaths().lsphpCLI }

// OpenLiteSpeedBinaryPath exposes the configured server binary for diagnostics.
func OpenLiteSpeedBinaryPath() string { return currentOLSRuntimePaths().binary }

// ReloadOpenLiteSpeed validates the complete configuration before restarting
// lshttpd. Replacing the managed LSPHP workers also clears their shared OPcache.
func ReloadOpenLiteSpeed() error {
	_, err := testAndRestartOpenLiteSpeed()
	return err
}

func validateOLSScalar(label, value string, absolute bool) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", fmt.Errorf("%s不能为空", label)
	}
	if strings.ContainsAny(value, "\r\n{}\x00") {
		return "", fmt.Errorf("%s包含不允许的字符", label)
	}
	if absolute && !filepath.IsAbs(value) {
		return "", fmt.Errorf("%s必须是绝对路径: %s", label, value)
	}
	return value, nil
}

func normalizeOLSDomains(primary string, aliases []string) ([]string, error) {
	all := append([]string{primary}, aliases...)
	seen := make(map[string]bool, len(all))
	domains := make([]string, 0, len(all))
	for _, raw := range all {
		domain := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(raw), "."))
		if !IsValidDomain(domain) {
			return nil, fmt.Errorf("域名格式不合法: %s", raw)
		}
		if !seen[domain] {
			seen[domain] = true
			domains = append(domains, domain)
		}
	}
	return domains, nil
}

// NormalizeAliasRedirectMode limits generated rewrite directives to the three
// panel-owned policies. Empty values are treated as the legacy "serve" mode so
// old databases and hand-built test fixtures keep their previous behaviour.
func NormalizeAliasRedirectMode(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return AliasRedirectServe, nil
	}
	switch value {
	case AliasRedirectServe, AliasRedirectPermanent, AliasRedirectTemporary:
		return value, nil
	default:
		return "", fmt.Errorf("附加域名处理方式无效: %s", value)
	}
}

func writeHTTPSRedirectRule(out *strings.Builder, domain string) {
	fmt.Fprintf(out, "RewriteCond %%{HTTP_HOST} ^%s(?::[0-9]+)?$ [NC]\n", regexp.QuoteMeta(domain))
	out.WriteString("RewriteCond %{HTTPS} off\n")
	fmt.Fprintf(out, "RewriteRule ^/?(.*)$ https://%s/$1 [R=301,L]\n", domain)
}

func olsSocketAddress(proxy string) (string, error) {
	value := strings.TrimSpace(proxy)
	value = strings.TrimPrefix(value, "unix:")
	if value == "" || !filepath.IsAbs(value) || strings.ContainsAny(value, "\r\n{}\x00 ") {
		return "", fmt.Errorf("LSPHP Socket 路径无效: %s", proxy)
	}
	if err := validateUnixSocketPath(value); err != nil {
		return "", err
	}
	return "uds://" + strings.TrimPrefix(filepath.ToSlash(value), "/"), nil
}

// renderOLSVHostConfig renders an OpenLiteSpeed plain-text virtual-host file.
// The first four metadata lines are consumed only by OLS WPanel when it
// atomically rebuilds the shared HTTP/HTTPS listener mappings.
func renderOLSVHostConfig(data *OLSVHostData) (string, error) {
	if data == nil {
		return "", errors.New("站点配置为空")
	}
	domains, err := normalizeOLSDomains(data.Domain, data.Aliases)
	if err != nil {
		return "", err
	}
	aliasRedirectMode, err := NormalizeAliasRedirectMode(data.AliasRedirectMode)
	if err != nil {
		return "", err
	}
	docRoot, err := validateOLSScalar("网站根目录", data.WebRoot, true)
	if err != nil {
		return "", err
	}
	logDir, err := validateOLSScalar("日志目录", data.LogDir, true)
	if err != nil {
		return "", err
	}
	if !olsSafeUserPattern.MatchString(data.SystemUser) {
		return "", fmt.Errorf("站点系统用户无效: %s", data.SystemUser)
	}
	socket, err := olsSocketAddress(data.PHPProxy)
	if err != nil {
		return "", err
	}
	vhostName := "olsw_" + buildSiteName(domains[0])
	if !olsSafeNamePattern.MatchString(vhostName) {
		return "", fmt.Errorf("OpenLiteSpeed 虚拟主机名无效: %s", vhostName)
	}
	handlerName := "lsphp_" + buildSiteName(domains[0])
	maxChildren := data.PHPMaxChildren
	if maxChildren <= 0 || maxChildren > 1000 {
		maxChildren = 10
	}
	phpCfg := LoadPHPRuntimeConfig()
	lsphpPath := strings.TrimSpace(data.LSPHPBinary)
	if lsphpPath == "" {
		lsphpPath = currentOLSRuntimePaths().lsphp
	}
	lsphp, err := validateOLSScalar("LSPHP 程序", lsphpPath, true)
	if err != nil {
		return "", err
	}
	pluginConfigPath, err := validateOLSScalar("站点插件身份文件", sitePluginConfigPath(domains[0]), true)
	if err != nil {
		return "", err
	}
	// Every creation, migration, SSL and regeneration path reaches this renderer.
	// Read the global policy here so hand-built vhost data cannot silently omit it.
	securityData := *data
	if data.SiteType == "wordpress" {
		securityData.SQLiBlockEnabled, securityData.SQLiAutoBanLog = loadOLSSQLiProtectionSettings()
	}

	var out strings.Builder
	fmt.Fprintf(&out, "%s1\n", olsMetadataFormatPrefix)
	fmt.Fprintf(&out, "%s%s\n", olsMetadataVHostPrefix, vhostName)
	fmt.Fprintf(&out, "%s%s\n", olsMetadataDomainsPrefix, strings.Join(domains, ","))
	fmt.Fprintf(&out, "%s%s\n", olsMetadataRootPrefix, docRoot)
	fmt.Fprintf(&out, "# OLS WPanel Generated — %s\n", data.TemplateVer)
	fmt.Fprintf(&out, "# Site: %s\n\n", domains[0])
	fmt.Fprintf(&out, "docRoot                 %s\n", docRoot)
	fmt.Fprintf(&out, "vhDomain                %s\n", domains[0])
	if len(domains) > 1 {
		fmt.Fprintf(&out, "vhAliases               %s\n", strings.Join(domains[1:], ","))
	}
	out.WriteString("adminEmails             root@localhost\n")
	out.WriteString("enableGzip              1\n")
	out.WriteString("enableBr                1\n\n")

	fmt.Fprintf(&out, "errorlog %s/error.log {\n", logDir)
	out.WriteString("  useServer              0\n")
	out.WriteString("  logLevel               WARN\n")
	out.WriteString("  rollingSize            20M\n")
	out.WriteString("  keepDays               14\n")
	out.WriteString("  compressArchive        1\n")
	out.WriteString("}\n\n")
	if data.AccessLogMode != "off" || data.SiteType == "wordpress" {
		fmt.Fprintf(&out, "accesslog %s/access.log {\n", logDir)
		out.WriteString("  useServer              0\n")
		logFormat := `%h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-Agent}i"`
		if data.SiteType == "wordpress" && (data.AccessLogMode == "off" || data.AccessLogMode == "error_only" || data.AccessLogMode == "") {
			// Security evidence remains available without logging query strings,
			// referrers or user agents when full access logging is disabled.
			logFormat = `%h %l %u %t "%m %U %H" %>s %b "-" "-"`
		}
		logFormat += " " + olsSecurityLogFields
		fmt.Fprintf(&out, "  logFormat              \"%s\"\n", strings.ReplaceAll(logFormat, `"`, `\"`))
		out.WriteString("  logHeaders             5\n")
		out.WriteString("  rollingSize            20M\n")
		out.WriteString("  keepDays               14\n")
		out.WriteString("  compressArchive        1\n")
		out.WriteString("}\n\n")
	}
	out.WriteString("index {\n  useServer              0\n  indexFiles             index.php,index.html,index.htm\n}\n\n")
	out.WriteString("scripthandler {\n")
	fmt.Fprintf(&out, "  add                    lsapi:%s php\n", handlerName)
	out.WriteString("}\n\n")
	fmt.Fprintf(&out, "extprocessor %s {\n", handlerName)
	out.WriteString("  type                   lsapi\n")
	fmt.Fprintf(&out, "  address                %s\n", socket)
	fmt.Fprintf(&out, "  maxConns               %d\n", maxChildren)
	fmt.Fprintf(&out, "  env                    PHP_LSAPI_CHILDREN=%d\n", maxChildren)
	out.WriteString("  env                    PHP_LSAPI_MAX_IDLE=300\n")
	out.WriteString("  env                    PHP_LSAPI_MAX_REQUESTS=500\n")
	out.WriteString("  env                    LSAPI_AVOID_FORK=200M\n")
	out.WriteString("  env                    LSPHP_ENABLE_USER_INI=on\n")
	fmt.Fprintf(&out, "  env                    %s=%s\n", sitePluginConfigEnvName, pluginConfigPath)
	out.WriteString("  initTimeout            60\n")
	out.WriteString("  retryTimeout           0\n")
	out.WriteString("  persistConn            1\n")
	out.WriteString("  respBuffer             0\n")
	out.WriteString("  autoStart              1\n")
	fmt.Fprintf(&out, "  path                   %s\n", lsphp)
	out.WriteString("  backlog                100\n")
	out.WriteString("  instances              1\n")
	fmt.Fprintf(&out, "  extUser                %s\n", data.SystemUser)
	fmt.Fprintf(&out, "  extGroup               %s\n", data.SystemUser)
	out.WriteString("  runOnStartUp           1\n")
	out.WriteString("  priority               0\n")
	out.WriteString("  memSoftLimit           0\n")
	out.WriteString("  memHardLimit           0\n")
	out.WriteString("  procSoftLimit          400\n")
	out.WriteString("  procHardLimit          500\n")
	out.WriteString("}\n\n")

	out.WriteString("phpIniOverride {\n")
	openBaseDir := sitePHPOpenBaseDir(docRoot, domains[0])
	if data.SiteType == "wordpress" {
		// The WordPress login-failure hook can write only its own site's log.
		openBaseDir += ":" + logDir
	}
	fmt.Fprintf(&out, "  php_admin_value open_basedir \"%s\"\n", openBaseDir)
	fmt.Fprintf(&out, "  php_admin_value upload_max_filesize %s\n", phpCfg.UploadMaxFilesize)
	fmt.Fprintf(&out, "  php_admin_value post_max_size %s\n", phpCfg.PostMaxSize)
	fmt.Fprintf(&out, "  php_admin_value max_execution_time %s\n", phpCfg.MaxExecutionTime)
	fmt.Fprintf(&out, "  php_admin_value max_input_time %s\n", phpCfg.MaxInputTime)
	fmt.Fprintf(&out, "  php_admin_value memory_limit %s\n", phpCfg.MemoryLimit)
	fmt.Fprintf(&out, "  php_admin_value disable_functions \"%s\"\n", sitePHPDisabledFunctions())
	fmt.Fprintf(&out, "  php_admin_value error_log %s/php-error.log\n", logDir)
	out.WriteString("  php_admin_flag display_errors Off\n")
	out.WriteString("  php_admin_flag log_errors On\n")
	out.WriteString("  php_admin_flag allow_url_include Off\n")
	out.WriteString("}\n\n")

	out.WriteString("context / {\n")
	fmt.Fprintf(&out, "  location               %s/\n", strings.TrimSuffix(docRoot, "/"))
	out.WriteString("  allowBrowse            1\n")
	out.WriteString("  addDefaultCharset      off\n")
	out.WriteString("}\n\n")
	out.WriteString("rewrite {\n")
	out.WriteString("  enable                 1\n")
	out.WriteString("  autoLoadHtaccess       1\n")
	out.WriteString("  rules                  <<<END_rules\n")
	out.WriteString(olsSiteSecurityRewriteRules(&securityData))
	if len(domains) > 1 && aliasRedirectMode != AliasRedirectServe {
		aliases := make([]string, 0, len(domains)-1)
		for _, alias := range domains[1:] {
			aliases = append(aliases, regexp.QuoteMeta(alias))
		}
		fmt.Fprintf(&out, "RewriteCond %%{HTTP_HOST} ^(?:%s)(?::[0-9]+)?$ [NC]\n", strings.Join(aliases, "|"))
		scheme := "http"
		if data.UseSSL {
			scheme = "https"
		}
		fmt.Fprintf(&out, "RewriteRule ^/?(.*)$ %s://%s/$1 [R=%s,L]\n", scheme, domains[0], aliasRedirectMode)
		if data.UseSSL {
			writeHTTPSRedirectRule(&out, domains[0])
		}
	} else if data.UseSSL {
		for _, domain := range domains {
			writeHTTPSRedirectRule(&out, domain)
		}
	}
	out.WriteString("END_rules\n")
	out.WriteString("}\n")

	if data.SiteType != "php" {
		cacheEnabled := 0
		if data.LSCacheEnabled {
			cacheEnabled = 1
		}
		cacheTTL := data.LSCacheTTL
		if cacheTTL < 30 || cacheTTL > 604800 {
			cacheTTL = 3600
		}
		out.WriteString("\nmodule cache {\n")
		out.WriteString("  ls_enabled             1\n")
		out.WriteString("  storagePath            $VH_ROOT/.lscache\n")
		out.WriteString("  checkPrivateCache      1\n")
		out.WriteString("  checkPublicCache       1\n")
		out.WriteString("  maxCacheObjSize        10000000\n")
		out.WriteString("  maxStaleAge            200\n")
		out.WriteString("  qsCache                1\n")
		out.WriteString("  reqCookieCache         1\n")
		out.WriteString("  respCookieCache        0\n")
		out.WriteString("  ignoreReqCacheCtrl     1\n")
		out.WriteString("  ignoreRespCacheCtrl    0\n")
		fmt.Fprintf(&out, "  enableCache            %d\n", cacheEnabled)
		fmt.Fprintf(&out, "  expireInSeconds        %d\n", cacheTTL)
		out.WriteString("  enablePrivateCache     0\n")
		out.WriteString("  privateExpireInSeconds 3600\n")
		out.WriteString("}\n")
	}

	if data.UseSSL {
		cert, err := validateOLSScalar("SSL 证书路径", data.SSLCertPath, true)
		if err != nil {
			return "", err
		}
		key, err := validateOLSScalar("SSL 私钥路径", data.SSLKeyPath, true)
		if err != nil {
			return "", err
		}
		fmt.Fprintf(&out, "\nvhssl {\n  keyFile                %s\n  certFile               %s\n  certChain              1\n  sslProtocol            30\n}\n", key, cert)
	}

	return out.String(), nil
}

func parseOLSVHostMetadata(content, configFile string) (olsVHostMetadata, error) {
	meta := olsVHostMetadata{configFile: filepath.Clean(configFile)}
	scanner := bufio.NewScanner(strings.NewReader(content))
	format := ""
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, olsMetadataFormatPrefix):
			format = strings.TrimSpace(strings.TrimPrefix(line, olsMetadataFormatPrefix))
		case strings.HasPrefix(line, olsMetadataVHostPrefix):
			meta.name = strings.TrimSpace(strings.TrimPrefix(line, olsMetadataVHostPrefix))
		case strings.HasPrefix(line, olsMetadataDomainsPrefix):
			raw := strings.Split(strings.TrimSpace(strings.TrimPrefix(line, olsMetadataDomainsPrefix)), ",")
			for _, domain := range raw {
				domain = strings.TrimSpace(domain)
				if domain != "" {
					meta.domains = append(meta.domains, domain)
				}
			}
		case strings.HasPrefix(line, olsMetadataRootPrefix):
			meta.vhRoot = strings.TrimSpace(strings.TrimPrefix(line, olsMetadataRootPrefix))
		}
		if len(meta.domains) > 0 && meta.name != "" && meta.vhRoot != "" && format != "" {
			break
		}
	}
	if err := scanner.Err(); err != nil {
		return meta, err
	}
	if format != "1" {
		return meta, fmt.Errorf("不支持的 OLS WPanel 站点配置格式: %q", format)
	}
	if !olsSafeNamePattern.MatchString(meta.name) {
		return meta, fmt.Errorf("OpenLiteSpeed 虚拟主机名无效: %s", meta.name)
	}
	if len(meta.domains) == 0 {
		return meta, errors.New("OpenLiteSpeed 虚拟主机缺少域名元数据")
	}
	if _, err := normalizeOLSDomains(meta.domains[0], meta.domains[1:]); err != nil {
		return meta, err
	}
	if _, err := validateOLSScalar("虚拟主机根目录", meta.vhRoot, true); err != nil {
		return meta, err
	}
	if _, err := validateOLSScalar("虚拟主机配置路径", meta.configFile, true); err != nil {
		return meta, err
	}
	return meta, nil
}

func validateOLSVHostContent(content, targetPath string) error {
	if len(content) == 0 || len(content) > 2<<20 {
		return fmt.Errorf("OpenLiteSpeed 站点配置大小无效")
	}
	if strings.Count(content, "{") != strings.Count(content, "}") {
		return fmt.Errorf("OpenLiteSpeed 站点配置括号不平衡")
	}
	_, err := parseOLSVHostMetadata(content, targetPath)
	return err
}

func renderOLSManagedRegistry(enabledDir string) (string, error) {
	entries, err := os.ReadDir(enabledDir)
	if err != nil {
		if os.IsNotExist(err) {
			entries = nil
		} else {
			return "", err
		}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	metas := make([]olsVHostMetadata, 0, len(entries))
	seenNames := map[string]bool{}
	seenDomains := map[string]bool{}
	availableDir := filepath.Join(filepath.Dir(filepath.Clean(enabledDir)), "sites-available")
	if config.AppConfig != nil && strings.TrimSpace(config.AppConfig.Paths.OLSVHostsAvailable) != "" {
		availableDir = filepath.Clean(config.AppConfig.Paths.OLSVHostsAvailable)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".conf") {
			continue
		}
		enabledPath := filepath.Join(enabledDir, entry.Name())
		targetPath := enabledPath
		entryInfo, infoErr := os.Lstat(enabledPath)
		if infoErr != nil {
			return "", fmt.Errorf("检查站点启用项失败 %s: %w", enabledPath, infoErr)
		}
		if entryInfo.Mode()&os.ModeSymlink != 0 {
			target, readErr := os.Readlink(enabledPath)
			if readErr != nil {
				return "", fmt.Errorf("读取站点启用链接失败 %s: %w", enabledPath, readErr)
			}
			if filepath.IsAbs(target) {
				targetPath = filepath.Clean(target)
			} else {
				targetPath = filepath.Clean(filepath.Join(enabledDir, target))
			}
			if _, pathErr := managedSubpath(availableDir, targetPath, "OpenLiteSpeed 虚拟主机配置"); pathErr != nil {
				return "", pathErr
			}
		} else {
			return "", fmt.Errorf("OpenLiteSpeed 启用项必须是受管符号链接: %s", enabledPath)
		}
		content, readErr := os.ReadFile(enabledPath)
		if readErr != nil {
			return "", fmt.Errorf("读取已启用站点配置失败 %s: %w", enabledPath, readErr)
		}
		meta, parseErr := parseOLSVHostMetadata(string(content), targetPath)
		if parseErr != nil {
			return "", fmt.Errorf("站点配置元数据无效 %s: %w", enabledPath, parseErr)
		}
		if seenNames[meta.name] {
			return "", fmt.Errorf("OpenLiteSpeed 虚拟主机名重复: %s", meta.name)
		}
		seenNames[meta.name] = true
		for _, domain := range meta.domains {
			if seenDomains[domain] {
				return "", fmt.Errorf("OpenLiteSpeed 域名映射重复: %s", domain)
			}
			seenDomains[domain] = true
		}
		metas = append(metas, meta)
	}

	paths := currentOLSRuntimePaths()
	defaultRoot, defaultConfig := olsDefaultVHostPaths(paths)
	var out strings.Builder
	out.WriteString("# OLS WPanel managed OpenLiteSpeed registry. DO NOT EDIT.\n")
	out.WriteString("# Generated atomically from the enabled-site directory.\n\n")
	fmt.Fprintf(&out, "virtualHost %s {\n", olsDefaultVHostName)
	fmt.Fprintf(&out, "  vhRoot                 %s/\n", filepath.ToSlash(defaultRoot))
	out.WriteString("  allowSymbolLink        0\n")
	out.WriteString("  enableScript           0\n")
	out.WriteString("  restrained             1\n")
	out.WriteString("  setUIDMode             0\n")
	fmt.Fprintf(&out, "  configFile             %s\n", filepath.ToSlash(defaultConfig))
	out.WriteString("}\n\n")
	for _, meta := range metas {
		fmt.Fprintf(&out, "virtualHost %s {\n", meta.name)
		fmt.Fprintf(&out, "  vhRoot                 %s/\n", strings.TrimSuffix(meta.vhRoot, "/"))
		out.WriteString("  allowSymbolLink        1\n")
		out.WriteString("  enableScript           1\n")
		out.WriteString("  restrained             1\n")
		out.WriteString("  setUIDMode             2\n")
		fmt.Fprintf(&out, "  configFile             %s\n", filepath.ToSlash(meta.configFile))
		out.WriteString("}\n\n")
	}
	out.WriteString("listener OLSWPanelHTTP {\n  address                 *:80\n  secure                  0\n")
	for _, meta := range metas {
		fmt.Fprintf(&out, "  map                    %s %s\n", meta.name, strings.Join(meta.domains, ","))
	}
	fmt.Fprintf(&out, "  map                    %s *\n", olsDefaultVHostName)
	out.WriteString("}\n\n")
	out.WriteString("listener OLSWPanelHTTPS {\n  address                 *:443\n  secure                  1\n")
	fmt.Fprintf(&out, "  keyFile                 %s\n", filepath.ToSlash(paths.listenerKey))
	fmt.Fprintf(&out, "  certFile                %s\n", filepath.ToSlash(paths.listenerCert))
	out.WriteString("  certChain               0\n  sslProtocol             30\n")
	for _, meta := range metas {
		fmt.Fprintf(&out, "  map                    %s %s\n", meta.name, strings.Join(meta.domains, ","))
	}
	fmt.Fprintf(&out, "  map                    %s *\n", olsDefaultVHostName)
	out.WriteString("}\n")
	return out.String(), nil
}

func olsDefaultVHostPaths(paths olsRuntimePaths) (string, string) {
	base := filepath.Dir(paths.managed)
	return filepath.Join(paths.root, "html", "ols-wpanel-default"), filepath.Join(base, "default-vhost.conf")
}

func ensureOLSDefaultVHost(paths olsRuntimePaths) error {
	root, configPath := olsDefaultVHostPaths(paths)
	if info, err := os.Lstat(root); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("OpenLiteSpeed 默认虚拟主机根目录不安全: %s", root)
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	if info, err := os.Lstat(configPath); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("OpenLiteSpeed 默认虚拟主机配置不得为符号链接: %s", configPath)
	} else if err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := ensurePanelACMEPublicRoot(paths); err != nil {
		return fmt.Errorf("创建 OpenLiteSpeed 默认虚拟主机根目录失败: %w", err)
	}
	account, err := lookupOLSDefaultVHostUser("www-data")
	if err != nil {
		return fmt.Errorf("查找 OpenLiteSpeed 默认虚拟主机用户 www-data 失败: %w", err)
	}
	uid, err := strconv.Atoi(account.Uid)
	if err != nil || uid < 11 {
		return fmt.Errorf("www-data UID 不符合 OpenLiteSpeed 最低安全要求: %q", account.Uid)
	}
	gid, err := strconv.Atoi(account.Gid)
	if err != nil || gid < 10 {
		return fmt.Errorf("www-data GID 不符合 OpenLiteSpeed 最低安全要求: %q", account.Gid)
	}
	if err := chownOLSDefaultVHostRoot(root, uid, gid); err != nil {
		return fmt.Errorf("设置 OpenLiteSpeed 默认虚拟主机目录所有者失败: %w", err)
	}
	if err := os.Chmod(root, 0755); err != nil {
		return fmt.Errorf("设置 OpenLiteSpeed 默认虚拟主机目录权限失败: %w", err)
	}
	content := fmt.Sprintf(`docRoot                 %s/
vhDomain                ols-wpanel.invalid
adminEmails             root@localhost
enableGzip              0
enableBr                0

index {
  useServer              0
  indexFiles             index.html
}

context / {
  location               %s/
  allowBrowse            0
  addDefaultCharset      off
}
`, filepath.ToSlash(root), filepath.ToSlash(root))
	if err := ensurePanelACMEChallengeDirectory(root); err != nil {
		return err
	}
	content += panelACMEContext(root)
	if err := writeOLSFileAtomic(configPath, []byte(content), 0640); err != nil {
		return fmt.Errorf("写入 OpenLiteSpeed 默认虚拟主机配置失败: %w", err)
	}
	return nil
}

func writeOLSFileAtomic(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".ols-wpanel-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpPath, mode); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	return nil
}

func restoreOLSFile(path string, old []byte, existed bool, mode os.FileMode) error {
	if existed {
		return writeOLSFileAtomic(path, old, mode)
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func testAndRestartOpenLiteSpeed() ([]byte, error) {
	paths := currentOLSRuntimePaths()
	testOut, err := runOLSCommand(paths.binary, "-t")
	if err != nil {
		return testOut, fmt.Errorf("OpenLiteSpeed 配置检查失败: %s", strings.TrimSpace(string(testOut)))
	}
	restartOut, err := runOLSCommand("systemctl", "restart", "lshttpd")
	if err != nil {
		return restartOut, fmt.Errorf("OpenLiteSpeed 优雅重载失败: %s", strings.TrimSpace(string(restartOut)))
	}
	return append(testOut, restartOut...), nil
}

func reloadOLSManagedRegistry(enabledDir string) ([]byte, error) {
	paths := currentOLSRuntimePaths()
	if err := ensureOLSDefaultVHost(paths); err != nil {
		return nil, err
	}
	content, err := renderOLSManagedRegistry(enabledDir)
	if err != nil {
		return nil, err
	}
	old, oldErr := os.ReadFile(paths.managed)
	existed := oldErr == nil
	if oldErr != nil && !os.IsNotExist(oldErr) {
		return nil, oldErr
	}
	if err := writeOLSFileAtomic(paths.managed, []byte(content), 0640); err != nil {
		return nil, fmt.Errorf("写入 OpenLiteSpeed 站点注册表失败: %w", err)
	}
	out, applyErr := testAndRestartOpenLiteSpeed()
	if applyErr == nil {
		return out, nil
	}
	restoreErr := restoreOLSFile(paths.managed, old, existed, 0640)
	_, restartErr := testAndRestartOpenLiteSpeed()
	if restoreErr != nil || restartErr != nil {
		return out, fmt.Errorf("%v；恢复旧注册表失败: %v；恢复后重载失败: %v", applyErr, restoreErr, restartErr)
	}
	return out, fmt.Errorf("%v；旧 OpenLiteSpeed 注册表已恢复", applyErr)
}

func applyOLSVHostConfig(engine *TemplateEngine, content, targetPath, enabledPath string) error {
	if err := validateOLSVHostContent(content, targetPath); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(targetPath), 0750); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(enabledPath), 0750); err != nil {
		return err
	}
	oldConfig, oldConfigErr := os.ReadFile(targetPath)
	hadOldConfig := oldConfigErr == nil
	if oldConfigErr != nil && !os.IsNotExist(oldConfigErr) {
		return oldConfigErr
	}
	oldEnabledTarget, oldEnabledErr := os.Readlink(enabledPath)
	hadOldEnabledLink := oldEnabledErr == nil
	if oldEnabledErr != nil && !os.IsNotExist(oldEnabledErr) && !errors.Is(oldEnabledErr, os.ErrInvalid) {
		return oldEnabledErr
	}
	restore := func() error {
		var failures []string
		if err := restoreOLSFile(targetPath, oldConfig, hadOldConfig, 0640); err != nil {
			failures = append(failures, err.Error())
		}
		if err := os.Remove(enabledPath); err != nil && !os.IsNotExist(err) {
			failures = append(failures, err.Error())
		}
		if hadOldEnabledLink {
			if err := os.Symlink(oldEnabledTarget, enabledPath); err != nil {
				failures = append(failures, err.Error())
			}
		}
		if _, err := reloadOLSManagedRegistry(filepath.Dir(enabledPath)); err != nil {
			failures = append(failures, err.Error())
		}
		if len(failures) > 0 {
			return errors.New(strings.Join(failures, "; "))
		}
		return nil
	}

	if err := writeOLSFileAtomic(targetPath, []byte(content), 0640); err != nil {
		return fmt.Errorf("写入 OpenLiteSpeed 虚拟主机配置失败: %w", err)
	}
	if err := atomicReplaceSymlink(enabledPath, targetPath); err != nil {
		_ = restoreOLSFile(targetPath, oldConfig, hadOldConfig, 0640)
		return fmt.Errorf("启用 OpenLiteSpeed 虚拟主机失败: %w", err)
	}
	if _, err := reloadOLSManagedRegistry(filepath.Dir(enabledPath)); err != nil {
		if restoreErr := restore(); restoreErr != nil {
			return fmt.Errorf("应用 OpenLiteSpeed 配置失败: %v；自动恢复不完整: %w", err, restoreErr)
		}
		return fmt.Errorf("应用 OpenLiteSpeed 配置失败，旧状态已恢复: %w", err)
	}
	if engine != nil && engine.BackupDir != "" && hadOldConfig && !bytes.Equal(oldConfig, []byte(content)) {
		backupDir := filepath.Join(engine.BackupDir, "openlitespeed")
		_ = os.MkdirAll(backupDir, 0750)
		backupName := filepath.Base(targetPath) + ".bak." + strconv.FormatInt(time.Now().UnixNano(), 10)
		_ = os.WriteFile(filepath.Join(backupDir, backupName), oldConfig, 0600)
	}
	return nil
}
