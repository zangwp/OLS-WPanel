package executor

import (
	"fmt"

	"github.com/zangwp/OLS-WPanel/internal/database"
)

const (
	defaultBotRateLimitRPM   = 30
	defaultBotRateLimitBurst = 20
)

func ApplyRateLimitSettings() error {
	ipEnabled, ipRPM, ipBurst := GetRateLimitSettings()
	botEnabled, botRPM, botBurst := GetBotRateLimitSettings()
	return ensureOLSRateLimitCompatibility(ipEnabled, ipRPM, ipBurst, botEnabled, botRPM, botBurst)
}

func EnsureLimitReqStatus() error {
	return nil
}

func EnsureRateLimit(enabled bool, rpm, burst int) error {
	botEnabled, botRPM, botBurst := GetBotRateLimitSettings()
	return ensureOLSRateLimitCompatibility(enabled, rpm, burst, botEnabled, botRPM, botBurst)
}

func EnsureBotRateLimit(enabled bool, rpm, burst int) error {
	ipEnabled, ipRPM, ipBurst := GetRateLimitSettings()
	return ensureOLSRateLimitCompatibility(ipEnabled, ipRPM, ipBurst, enabled, rpm, burst)
}

func ensureOLSRateLimitCompatibility(ipEnabled bool, ipRPM, ipBurst int, botEnabled bool, botRPM, botBurst int) error {
	if ipEnabled || botEnabled {
		return fmt.Errorf("当前 OpenLiteSpeed 版本暂不支持面板动态请求限速；请保持该选项关闭")
	}
	return nil
}

func GetRateLimitSettings() (enabled bool, rpm int, burst int) {
	db := database.GetDB()
	if db == nil {
		return false, 60, 300
	}

	var sEnabled, sRPM, sBurst string
	db.QueryRow(`SELECT svalue FROM security_settings WHERE skey = 'rate_limit_enabled'`).Scan(&sEnabled)
	db.QueryRow(`SELECT svalue FROM security_settings WHERE skey = 'rate_limit_rpm'`).Scan(&sRPM)
	db.QueryRow(`SELECT svalue FROM security_settings WHERE skey = 'rate_limit_burst'`).Scan(&sBurst)

	enabled = sEnabled != "false"
	rpm = parseIntOr(sRPM, 60)
	burst = parseIntOr(sBurst, 300)
	return
}

func GetBotRateLimitSettings() (enabled bool, rpm int, burst int) {
	db := database.GetDB()
	if db == nil {
		return false, defaultBotRateLimitRPM, defaultBotRateLimitBurst
	}

	var sEnabled, sRPM, sBurst string
	db.QueryRow(`SELECT svalue FROM security_settings WHERE skey = 'bot_limit_enabled'`).Scan(&sEnabled)
	db.QueryRow(`SELECT svalue FROM security_settings WHERE skey = 'bot_limit_rpm'`).Scan(&sRPM)
	db.QueryRow(`SELECT svalue FROM security_settings WHERE skey = 'bot_limit_burst'`).Scan(&sBurst)

	enabled = sEnabled == "true"
	rpm = parseIntOr(sRPM, defaultBotRateLimitRPM)
	burst = parseIntOr(sBurst, defaultBotRateLimitBurst)
	return
}
