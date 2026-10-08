package executor

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"html"
	"strings"
	"time"

	"github.com/zangwp/OLS-WPanel/internal/accountsecurity"
	"github.com/zangwp/OLS-WPanel/internal/database"
)

func accountSecurityChannelConfig(ctx context.Context, db *sql.DB) (*SMTPConfig, *WebhookConfig, error) {
	if db == nil {
		return nil, nil, errors.New("notification settings database unavailable")
	}
	rows, err := db.QueryContext(ctx, `SELECT skey,svalue FROM security_settings WHERE skey IN ('smtp_host','smtp_port','smtp_encryption','smtp_user','smtp_pass','admin_email','webhook_channel','webhook_url')`)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	settings := make(map[string]string)
	for rows.Next() {
		var key, value string
		if err := rows.Scan(&key, &value); err != nil {
			return nil, nil, err
		}
		settings[key] = value
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	smtp := &SMTPConfig{Host: settings["smtp_host"], Port: settings["smtp_port"], Encryption: settings["smtp_encryption"], User: settings["smtp_user"], Pass: settings["smtp_pass"], AdminEmail: settings["admin_email"]}
	webhook := &WebhookConfig{Channel: settings["webhook_channel"], URL: settings["webhook_url"]}
	return smtp, webhook, nil
}

func accountSMTPConfigured(cfg *SMTPConfig) bool {
	return cfg != nil && cfg.Host != "" && cfg.Port != "" && cfg.User != "" && cfg.Pass != "" && cfg.AdminEmail != ""
}

func AccountSecurityNotificationChannels(ctx context.Context, db *sql.DB) (bool, bool, error) {
	smtp, webhook, err := accountSecurityChannelConfig(ctx, db)
	if err != nil {
		return false, false, err
	}
	return accountSMTPConfigured(smtp), webhookConfigured(webhook), nil
}

// Attach this callback at startup. Import direction stays executor -> audit,
// so audit persistence and tests never need a mail server or the executor.
func SendAccountSecurityNotification(ctx context.Context, event accountsecurity.Event) error {
	smtp, webhook, err := accountSecurityChannelConfig(ctx, database.GetDB())
	if err != nil {
		return err
	}
	return sendAccountSecurityNotification(ctx, event, smtp, webhook, sendMailWithConfig, sendWebhookWithConfig)
}

type accountMailSender func(context.Context, *SMTPConfig, string, string, string) error
type accountWebhookSender func(context.Context, *WebhookConfig, string, string) error

func sendAccountSecurityNotification(ctx context.Context, event accountsecurity.Event, smtp *SMTPConfig, webhook *WebhookConfig, mailSender accountMailSender, webhookSender accountWebhookSender) error {
	if !accountSMTPConfigured(smtp) && !webhookConfigured(webhook) {
		return accountsecurity.ErrNotificationsUnconfigured
	}
	subject := "OLS WPanel — 账户安全 / Account security"
	label := map[string]string{
		"login_success":       "新登录环境 / New sign-in environment",
		"recovery_used":       "已使用恢复码 / Recovery code used",
		"mfa_disabled":        "双重验证已关闭 / Two-factor authentication disabled",
		"credentials_changed": "登录凭据已更改 / Sign-in credentials changed",
	}[event.Event]
	if label == "" {
		return errors.New("unsupported account notification event")
	}
	body := fmt.Sprintf("%s\n账户 / Account: %s\nIP: %s\n浏览器 / User agent: %s\n时间 / Time (UTC): %s", label, event.Username, event.IP, event.UserAgent, event.CreatedAt.UTC().Format(time.RFC3339))
	if event.Event == "login_success" {
		body += "\n这是最近保留记录中首次出现的 IP 与浏览器组合（包括首次登录），不代表可靠的设备身份。 / This IP/browser pair is new to retained history, including the first sign-in; it is not a verified device identity."
	}
	body += "\n如非本人操作，请检查活动会话并修改登录凭据。 / If this was not you, review active sessions and change your credentials."
	var failures []error
	if accountSMTPConfigured(smtp) {
		mailCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
		err := mailSender(mailCtx, smtp, "", subject, "<p>"+strings.ReplaceAll(html.EscapeString(body), "\n", "<br>")+"</p>")
		cancel()
		if err != nil {
			failures = append(failures, errors.New("account security email delivery failed"))
		}
	}
	if webhookConfigured(webhook) {
		hookCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		err := webhookSender(hookCtx, webhook, subject, body)
		cancel()
		if err != nil {
			failures = append(failures, errors.New("account security webhook delivery failed"))
		}
	}
	return errors.Join(failures...)
}
