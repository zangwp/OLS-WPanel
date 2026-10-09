package executor

import (
	"fmt"
	"log"
	"os"
	"path"
	"strings"

	"github.com/zangwp/OLS-WPanel/internal/database"
)

const (
	defaultSiteLogRetentionDays = 14
	siteLogrotateDir            = "/etc/logrotate.d"
	siteLogRoot                 = "/www/wwwlogs"
)

func WriteSiteLogrotateConfig(domain, logDir string, retentionDays int) error {
	if !IsValidDomain(domain) {
		return fmt.Errorf("invalid domain for logrotate config: %s", domain)
	}

	confPath := path.Join(siteLogrotateDir, "olswpanel-"+domain)
	if retentionDays <= 0 {
		if err := os.Remove(confPath); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove logrotate config: %w", err)
		}
		return nil
	}

	cleanLogDir, err := cleanSiteLogrotateLogDir(logDir)
	if err != nil {
		return err
	}

	content := renderSiteLogrotateConfig(domain, cleanLogDir, retentionDays)
	if err := os.WriteFile(confPath, []byte(content), 0644); err != nil {
		return fmt.Errorf("write logrotate config: %w", err)
	}
	return nil
}

func EnsureAllSiteLogrotateConfigs() {
	db := database.GetDB()
	if db == nil {
		return
	}

	rows, err := db.Query("SELECT domain, log_dir, log_retention_days FROM websites")
	if err != nil {
		log.Printf("site logrotate scan skipped: %v", err)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var domain, logDir string
		retentionDays := defaultSiteLogRetentionDays
		if err := rows.Scan(&domain, &logDir, &retentionDays); err != nil {
			log.Printf("site logrotate row skipped: %v", err)
			continue
		}
		if err := WriteSiteLogrotateConfig(domain, logDir, retentionDays); err != nil {
			log.Printf("site logrotate config skipped for %s: %v", domain, err)
		}
	}
	if err := rows.Err(); err != nil {
		log.Printf("site logrotate scan ended with error: %v", err)
	}
}

func cleanSiteLogrotateLogDir(logDir string) (string, error) {
	root, err := fail2banWebsiteLogRoot()
	if err != nil {
		return "", err
	}
	clean, err := cleanFail2banWebsiteLogRoot(logDir)
	if err != nil {
		return "", err
	}
	if clean != root && !strings.HasPrefix(clean, root+"/") {
		return "", fmt.Errorf("log directory outside allowed root: %s", logDir)
	}
	return clean, nil
}

func renderSiteLogrotateConfig(domain, logDir string, retentionDays int) string {
	return fmt.Sprintf(`# OLS WPanel Generated - %s
%s/access.log
%s/error.log
%s/wp-security.log
%s/wp-login-security.log
%s/wp-sqli-security.log
%s/php-error.log
%s/php-slow.log {
    daily
    rotate %d
    missingok
    notifempty
    compress
    delaycompress
    dateext
    dateformat -%%Y-%%m-%%d
    dateyesterday
    copytruncate
}
`, domain, logDir, logDir, logDir, logDir, logDir, logDir, logDir, retentionDays)
}
