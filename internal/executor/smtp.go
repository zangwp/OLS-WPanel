package executor

import (
	"context"
	"crypto/tls"
	"fmt"
	"html"
	"net"
	"net/smtp"
	"strings"
	"time"

	"github.com/zangwp/OLS-WPanel/internal/database"
)

type SMTPConfig struct {
	Host       string
	Port       string
	Encryption string
	User       string
	Pass       string
	AdminEmail string
}

func GetSMTPConfig() *SMTPConfig {
	db := database.GetDB()
	if db == nil {
		return nil
	}
	cfg := &SMTPConfig{}
	db.QueryRow(`SELECT svalue FROM security_settings WHERE skey = 'smtp_host'`).Scan(&cfg.Host)
	db.QueryRow(`SELECT svalue FROM security_settings WHERE skey = 'smtp_port'`).Scan(&cfg.Port)
	db.QueryRow(`SELECT svalue FROM security_settings WHERE skey = 'smtp_encryption'`).Scan(&cfg.Encryption)
	db.QueryRow(`SELECT svalue FROM security_settings WHERE skey = 'smtp_user'`).Scan(&cfg.User)
	db.QueryRow(`SELECT svalue FROM security_settings WHERE skey = 'smtp_pass'`).Scan(&cfg.Pass)
	db.QueryRow(`SELECT svalue FROM security_settings WHERE skey = 'admin_email'`).Scan(&cfg.AdminEmail)
	return cfg
}

func SendMail(to, subject, body string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return SendMailContext(ctx, to, subject, body)
}

func SendMailContext(ctx context.Context, to, subject, body string) error {
	cfg := GetSMTPConfig()
	return sendMailWithConfig(ctx, cfg, to, subject, body)
}

func sendMailWithConfig(ctx context.Context, cfg *SMTPConfig, to, subject, body string) error {
	if cfg == nil || cfg.Host == "" || cfg.User == "" || cfg.Pass == "" {
		return fmt.Errorf("SMTP 未配置")
	}
	if to == "" {
		to = cfg.AdminEmail
	}
	if to == "" {
		return fmt.Errorf("管理员邮箱未设置")
	}

	addr := net.JoinHostPort(cfg.Host, cfg.Port)
	msg := buildMessage(cfg.User, to, subject, body)
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("SMTP 连接失败: %w", err)
	}
	defer conn.Close()
	deadline := time.Now().Add(30 * time.Second)
	if requested, ok := ctx.Deadline(); ok && requested.Before(deadline) {
		deadline = requested
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return err
	}
	stopCancel := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopCancel()

	switch cfg.Encryption {
	case "ssl":
		tlsCfg := &tls.Config{ServerName: cfg.Host}
		tlsConn := tls.Client(conn, tlsCfg)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			return fmt.Errorf("TLS 连接失败: %w", err)
		}
		client, err := smtp.NewClient(tlsConn, cfg.Host)
		if err != nil {
			return fmt.Errorf("SMTP 客户端创建失败: %w", err)
		}
		defer client.Quit()
		if err := authAndSend(client, cfg, to, msg); err != nil {
			return err
		}
	case "none":
		client, err := smtp.NewClient(conn, cfg.Host)
		if err != nil {
			return fmt.Errorf("SMTP 客户端创建失败: %w", err)
		}
		defer client.Quit()
		if err := authAndSend(client, cfg, to, msg); err != nil {
			return err
		}
	default: // starttls
		client, err := smtp.NewClient(conn, cfg.Host)
		if err != nil {
			return fmt.Errorf("SMTP 客户端创建失败: %w", err)
		}
		defer client.Quit()
		if err := client.StartTLS(&tls.Config{ServerName: cfg.Host}); err != nil {
			return fmt.Errorf("STARTTLS 失败: %w", err)
		}
		if err := authAndSend(client, cfg, to, msg); err != nil {
			return err
		}
	}
	return nil
}

func authAndSend(client *smtp.Client, cfg *SMTPConfig, to, msg string) error {
	auth := smtp.PlainAuth("", cfg.User, cfg.Pass, cfg.Host)
	if err := client.Auth(auth); err != nil {
		return fmt.Errorf("认证失败: %w", err)
	}
	if err := client.Mail(cfg.User); err != nil {
		return err
	}
	if err := client.Rcpt(to); err != nil {
		return err
	}
	wc, err := client.Data()
	if err != nil {
		return err
	}
	_, err = wc.Write([]byte(msg))
	closeErr := wc.Close()
	if err != nil {
		return err
	}
	return closeErr
}

func buildMessage(from, to, subject, body string) string {
	subject = strings.NewReplacer("\r", "", "\n", "").Replace(subject)
	to = strings.NewReplacer("\r", "", "\n", "").Replace(to)
	return fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n%s",
		from, to, subject, body)
}

func TestSMTP(to string) error {
	panelTitle := html.EscapeString(getPanelTitle())
	body := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; padding: 20px; color: #333;">
<p style="font-size: 15px;">如果您收到这封邮件，说明 SMTP 配置正确。</p>
<p style="font-size: 12px; color: #aaa; margin-top: 20px;">— 来自 %s 面板</p>
</body>
</html>`, panelTitle)
	return SendMail(to, getPanelTitle()+" — 测试邮件", body)
}
