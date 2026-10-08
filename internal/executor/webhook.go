package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/zangwp/OLS-WPanel/internal/database"
)

type WebhookConfig struct {
	Channel string
	URL     string
}

func GetWebhookConfig() *WebhookConfig {
	db := database.GetDB()
	if db == nil {
		return nil
	}
	cfg := &WebhookConfig{}
	db.QueryRow("SELECT svalue FROM security_settings WHERE skey = 'webhook_channel'").Scan(&cfg.Channel)
	db.QueryRow("SELECT svalue FROM security_settings WHERE skey = 'webhook_url'").Scan(&cfg.URL)
	return cfg
}

func webhookConfigured(cfg *WebhookConfig) bool {
	return cfg != nil && cfg.URL != ""
}

func isBlockedIP(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsPrivate() || ip.IsUnspecified()
}

func isSafeWebhookURL(rawURL string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return isSafeWebhookURLContext(ctx, rawURL)
}

func isSafeWebhookURLContext(ctx context.Context, rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return err
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return fmt.Errorf("不支持的协议: %s", u.Scheme)
	}
	host := u.Hostname()
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return fmt.Errorf("无法解析主机名: %s", host)
	}
	for _, ip := range ips {
		if isBlockedIP(ip.IP) {
			return fmt.Errorf("不允许的内网地址: %s", ip.String())
		}
	}
	return nil
}

// safeWebhookClient returns an http.Client that checks the destination IP at
// connection time, preventing DNS rebinding attacks that could bypass the
// pre-flight isSafeWebhookURL check.
func safeWebhookClient() *http.Client {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				host, _, err := net.SplitHostPort(addr)
				if err != nil {
					return nil, err
				}
				ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
				if err != nil {
					return nil, err
				}
				_, port, _ := net.SplitHostPort(addr)
				return dialSafeWebhookAddresses(ctx, network, port, ips, dialer.DialContext)
			},
		},
	}
}

func dialSafeWebhookAddresses(ctx context.Context, network, port string, ips []net.IPAddr, dial func(context.Context, string, string) (net.Conn, error)) (net.Conn, error) {
	if len(ips) == 0 {
		return nil, fmt.Errorf("webhook: no destination addresses")
	}
	// Check the complete resolution before connecting to any address, then
	// preserve dual-stack fallback without performing an unchecked second DNS lookup.
	for _, ip := range ips {
		if isBlockedIP(ip.IP) {
			return nil, fmt.Errorf("webhook: 目标 IP 被禁止: %s", ip.String())
		}
	}
	var lastErr error
	for _, ip := range ips {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		conn, err := dial(ctx, network, net.JoinHostPort(ip.IP.String(), port))
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func SendWebhook(subject, body string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return SendWebhookContext(ctx, subject, body)
}

func SendWebhookContext(ctx context.Context, subject, body string) error {
	cfg := GetWebhookConfig()
	return sendWebhookWithConfig(ctx, cfg, subject, body)
}

func sendWebhookWithConfig(ctx context.Context, cfg *WebhookConfig, subject, body string) error {
	if !webhookConfigured(cfg) {
		return fmt.Errorf("Webhook 未配置")
	}

	if err := isSafeWebhookURLContext(ctx, cfg.URL); err != nil {
		return fmt.Errorf("Webhook URL 不安全: %w", err)
	}

	client := safeWebhookClient()
	defer client.CloseIdleConnections()

	if cfg.Channel == "bark" {
		return sendBarkContext(ctx, client, cfg.URL, subject, body)
	}

	payload, err := buildPayload(cfg.Channel, subject, body)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.URL, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("Webhook 请求失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("Webhook 返回错误状态: %d", resp.StatusCode)
	}
	return nil
}

func sendBark(client *http.Client, baseURL, title, body string) error {
	return sendBarkContext(context.Background(), client, baseURL, title, body)
}

func sendBarkContext(ctx context.Context, client *http.Client, baseURL, title, body string) error {
	u, err := url.Parse(baseURL)
	if err != nil {
		return fmt.Errorf("Bark URL 格式错误: %w", err)
	}
	u = u.JoinPath(url.PathEscape(title), url.PathEscape(body))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("Bark 请求失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("Bark 返回错误状态: %d", resp.StatusCode)
	}
	return nil
}

func buildPayload(channel, subject, body string) ([]byte, error) {
	content := subject
	if body != "" {
		content = subject + "\n" + body
	}

	var payload map[string]interface{}

	switch channel {
	case "wecom":
		payload = map[string]interface{}{
			"msgtype": "text",
			"text": map[string]string{
				"content": content,
			},
		}
	case "dingtalk":
		payload = map[string]interface{}{
			"msgtype": "text",
			"text": map[string]string{
				"content": content,
			},
		}
	case "feishu":
		payload = map[string]interface{}{
			"msg_type": "text",
			"content": map[string]string{
				"text": content,
			},
		}
	case "serverchan":
		payload = map[string]interface{}{
			"title": subject,
			"desp":  body,
		}
	case "custom":
		payload = map[string]interface{}{
			"title":   subject,
			"content": body,
			"time":    time.Now().Format("2006-01-02 15:04:05"),
		}
	default:
		return nil, fmt.Errorf("不支持的推送渠道: %s", channel)
	}

	return json.Marshal(payload)
}

func TestWebhook(channel, url string) error {
	if err := isSafeWebhookURL(url); err != nil {
		return fmt.Errorf("Webhook URL 不安全: %w", err)
	}

	title := getPanelTitle() + " — 测试消息"
	msg := "如果您收到这条消息，说明 Webhook 配置正确。"

	client := safeWebhookClient()

	if channel == "bark" {
		return sendBark(client, url, title, msg)
	}

	payload, err := buildPayload(channel, title, msg)
	if err != nil {
		return err
	}

	resp, err := client.Post(url, "application/json", bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("Webhook 请求失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("Webhook 返回错误状态: %d", resp.StatusCode)
	}
	return nil
}
