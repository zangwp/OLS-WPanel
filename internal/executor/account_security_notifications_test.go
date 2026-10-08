package executor

import (
	"bufio"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"net/smtp"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zangwp/OLS-WPanel/internal/accountsecurity"
	_ "modernc.org/sqlite"
)

func TestAccountNotificationsUseConfiguredChannelsWithoutSecretDisclosure(t *testing.T) {
	event := accountsecurity.Event{Username: "<admin>", Event: "login_success", IP: "192.0.2.1", UserAgent: "<script>alert(1)</script>", CreatedAt: time.Now(), Anomaly: true}
	smtp := &SMTPConfig{Host: "smtp.invalid", Port: "465", User: "user", Pass: "fixture-only-password", AdminEmail: "admin@example.invalid"}
	webhook := &WebhookConfig{Channel: "custom", URL: "https://example.invalid/fixture-secret"}
	mailCalls, hookCalls := 0, 0
	mail := func(ctx context.Context, _ *SMTPConfig, to, subject, body string) error {
		mailCalls++
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > 15*time.Second {
			t.Error("SMTP send lacks deadline")
		}
		if strings.Contains(body, "<script>") || !strings.Contains(body, "&lt;admin&gt;") || strings.Contains(body, smtp.Pass) {
			t.Error("unsafe email body")
		}
		return errors.New("transport failure including fixture-only-password")
	}
	hook := func(ctx context.Context, _ *WebhookConfig, subject, body string) error {
		hookCalls++
		if _, ok := ctx.Deadline(); !ok {
			t.Error("webhook lacks deadline")
		}
		if !strings.Contains(body, "New sign-in environment") || strings.Contains(body, webhook.URL) {
			t.Error("incorrect notification body")
		}
		return nil
	}
	err := sendAccountSecurityNotification(context.Background(), event, smtp, webhook, mail, hook)
	if err == nil || strings.Contains(err.Error(), smtp.Pass) || mailCalls != 1 || hookCalls != 1 {
		t.Fatalf("notification result or channel fallback incorrect: %v", err)
	}
	if err := sendAccountSecurityNotification(context.Background(), event, nil, nil, mail, hook); !errors.Is(err, accountsecurity.ErrNotificationsUnconfigured) {
		t.Fatal("missing config not reported")
	}
	if mailCalls != 1 || hookCalls != 1 {
		t.Fatal("unconfigured channel attempted a send")
	}
}

func TestAccountNotificationConfigurationFailureIsNotUnconfigured(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "notification.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, _, err := AccountSecurityNotificationChannels(context.Background(), db); err == nil {
		t.Fatal("database error hidden as no channels")
	}
	if _, err := db.Exec(`CREATE TABLE security_settings(skey TEXT PRIMARY KEY,svalue TEXT)`); err != nil {
		t.Fatal(err)
	}
	mail, hook, err := AccountSecurityNotificationChannels(context.Background(), db)
	if err != nil || mail || hook {
		t.Fatalf("empty configuration incorrect %v", err)
	}
}

func TestAccountNotificationSMTPHonorsCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	cfg := &SMTPConfig{Host: "127.0.0.1", Port: "1", User: "fixture", Pass: "fixture-only", AdminEmail: "admin@example.invalid"}
	// The pre-cancelled context stops before any connection or SMTP send.
	if err := sendMailWithConfig(ctx, cfg, "", "fixture", "fixture"); err == nil {
		t.Fatal("cancelled SMTP request succeeded")
	}
}

func TestAccountNotificationSMTPRejectAfterDataIsNotSuccess(t *testing.T) {
	// In-memory SMTP conversation: no socket, DNS or external message delivery.
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()
	_ = clientConn.SetDeadline(time.Now().Add(2 * time.Second))
	_ = serverConn.SetDeadline(time.Now().Add(2 * time.Second))
	done := make(chan struct{})
	go func() {
		defer close(done)
		reader := bufio.NewReader(serverConn)
		fmt.Fprint(serverConn, "220 fixture ESMTP\r\n")
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			switch {
			case strings.HasPrefix(line, "EHLO"):
				fmt.Fprint(serverConn, "250-fixture\r\n250 AUTH PLAIN\r\n")
			case strings.HasPrefix(line, "AUTH"):
				fmt.Fprint(serverConn, "235 accepted\r\n")
			case strings.HasPrefix(line, "MAIL"), strings.HasPrefix(line, "RCPT"):
				fmt.Fprint(serverConn, "250 accepted\r\n")
			case strings.HasPrefix(line, "DATA"):
				fmt.Fprint(serverConn, "354 send data\r\n")
				for {
					line, err = reader.ReadString('\n')
					if err != nil {
						return
					}
					if line == ".\r\n" {
						break
					}
				}
				fmt.Fprint(serverConn, "550 delivery rejected\r\n")
				return
			default:
				return
			}
		}
	}()
	client, err := smtp.NewClient(clientConn, "localhost")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	cfg := &SMTPConfig{Host: "localhost", User: "fixture@example.invalid", Pass: "fixture-only"}
	if err := authAndSend(client, cfg, "admin@example.invalid", "Subject: fixture\r\n\r\nfixture"); err == nil {
		t.Fatal("SMTP final rejection was reported as success")
	}
	<-done
}

func TestAccountNotificationWebhookCheckedDualStackFallback(t *testing.T) {
	ips := []net.IPAddr{{IP: net.ParseIP("2606:4700:4700::1111")}, {IP: net.ParseIP("1.1.1.1")}}
	var attempted []string
	client, peer := net.Pipe()
	defer client.Close()
	defer peer.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, err := dialSafeWebhookAddresses(ctx, "tcp", "443", ips, func(got context.Context, network, addr string) (net.Conn, error) {
		if got != ctx {
			t.Fatal("address fallback lost shared deadline")
		}
		attempted = append(attempted, addr)
		if len(attempted) == 1 {
			return nil, errors.New("fixture IPv6 unavailable")
		}
		return client, nil
	})
	if err != nil || conn != client || len(attempted) != 2 || attempted[1] != "1.1.1.1:443" {
		t.Fatalf("checked address fallback failed: %v %v", attempted, err)
	}
	called := false
	_, err = dialSafeWebhookAddresses(ctx, "tcp", "443", append(ips, net.IPAddr{IP: net.ParseIP("127.0.0.1")}), func(context.Context, string, string) (net.Conn, error) { called = true; return nil, nil })
	if err == nil || called {
		t.Fatal("mixed public/private DNS response permitted dialing")
	}
}
