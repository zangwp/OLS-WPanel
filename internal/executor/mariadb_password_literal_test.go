package executor

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/zangwp/OLS-WPanel/internal/config"
	"github.com/zangwp/OLS-WPanel/internal/models"
)

type passwordCommandReceipt struct {
	Args  []string
	Input string
}

func TestMariaDBPasswordMaskRevealsNoFragmentsOrLength(t *testing.T) {
	for _, password := range []string{"", "short", "12345678", "123456789", "long-password-fragments", "中文🔑密码", "line\npassword"} {
		if got := maskPassword(password); got != "********" {
			t.Fatalf("mask revealed password-dependent content: %q", got)
		}
	}
}

func TestMariaDBPasswordLiteralProcessHelper(t *testing.T) {
	if os.Getenv("OLS_PASSWORD_LITERAL_HELPER") != "1" {
		return
	}
	if os.Getenv("OLS_PASSWORD_LITERAL_SLOW") == "1" {
		time.Sleep(30 * time.Second)
		os.Exit(0)
	}
	input, err := io.ReadAll(os.Stdin)
	if err != nil {
		os.Exit(2)
	}
	body, err := json.Marshal(passwordCommandReceipt{Args: os.Args[3:], Input: string(input)})
	if err != nil || os.WriteFile(os.Getenv("OLS_PASSWORD_LITERAL_OUTPUT"), body, 0600) != nil {
		os.Exit(3)
	}
	if os.Getenv("OLS_PASSWORD_LITERAL_FAIL") == "1" {
		// Real clients can echo the query. Such stderr must never reach callers.
		_, _ = os.Stderr.Write(input)
		os.Exit(42)
	}
	os.Exit(0)
}

func passwordLiteralProcess(ctx context.Context, _ string, args ...string) *exec.Cmd {
	return exec.CommandContext(ctx, os.Args[0], append([]string{"-test.run=^TestMariaDBPasswordLiteralProcessHelper$", "--"}, args...)...)
}

func setupPasswordLiteralProcess(t *testing.T) (*config.Config, string) {
	t.Helper()
	old, timeout, oldConfig := runMariaDBPasswordCommand, mariaDBPasswordTimeout, config.AppConfig
	runMariaDBPasswordCommand = passwordLiteralProcess
	mariaDBPasswordTimeout = 5 * time.Second
	cfg := &config.Config{}
	cfg.MariaDB.RootUser, cfg.MariaDB.RootPassword = "root", "fixture-root-secret"
	config.AppConfig = cfg
	t.Cleanup(func() {
		runMariaDBPasswordCommand, mariaDBPasswordTimeout, config.AppConfig = old, timeout, oldConfig
	})
	t.Setenv("OLS_PASSWORD_LITERAL_HELPER", "1")
	output := filepath.Join(t.TempDir(), "receipt.json")
	t.Setenv("OLS_PASSWORD_LITERAL_OUTPUT", output)
	return cfg, output
}

func TestMariaDBPasswordSQLPreservesLiteralBytesAndUsesOnlyStdin(t *testing.T) {
	cfg, output := setupPasswordLiteralProcess(t)
	cases := []struct{ name, password, literal string }{
		{"plain", "plain-password", "'plain-password'"},
		{"quote", "can't", "'can''t'"},
		{"backslash", `a\b\n\0\`, `'a\b\n\0\'`},
		{"slash_and_quote", `a\'b`, `'a\''b'`},
		{"unicode", "中文密码🔑é", "'中文密码🔑é'"},
		{"newlines", "line1\r\nline2\n\tend", "'line1\r\nline2\n\tend'"},
		{"dollars", "$1 ${name} $$", "'$1 ${name} $$'"},
		{"statement_text", "x'; DROP USER 'root'@'localhost'; --", "'x''; DROP USER ''root''@''localhost''; --'"},
		{"client_command_text", "first\n\\! touch never\n\\C latin1\nDELIMITER //\nlast", "'first\n\\! touch never\n\\C latin1\nDELIMITER //\nlast'"},
	}
	wantArgs := []string{"--no-defaults", "--batch", "--binary-mode", "--local-infile=0", "--skip-reconnect", "--skip-auto-rehash", "--protocol=SOCKET", "--connect-timeout=10", "--default-character-set=utf8mb4", "-u", "root"}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := changeMariaDBPassword("site_user", tc.password, cfg); err != nil {
				t.Fatal(err)
			}
			body, err := os.ReadFile(output)
			if err != nil {
				t.Fatal(err)
			}
			var receipt passwordCommandReceipt
			if err := json.Unmarshal(body, &receipt); err != nil {
				t.Fatal(err)
			}
			want := "SET SESSION sql_mode='NO_BACKSLASH_ESCAPES';\nALTER USER 'site_user'@'localhost' IDENTIFIED BY " + tc.literal + ";\n"
			if receipt.Input != want || !reflect.DeepEqual(receipt.Args, wantArgs) {
				t.Fatalf("password bytes/client options changed: input=%q args=%q", receipt.Input, receipt.Args)
			}
		})
	}
}

func TestMariaDBPasswordInvalidTextAndIdentityStartNoProcess(t *testing.T) {
	cfg, output := setupPasswordLiteralProcess(t)
	cases := []struct{ name, user, password string }{
		{"nul", "site_user", "before\x00after"},
		{"invalid_utf8", "site_user", string([]byte{'a', 0xff, 'b'})},
		{"user_quote", "site_user'", "valid"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := changeMariaDBPassword(tc.user, tc.password, cfg); err == nil {
				t.Fatal("invalid identity/password accepted")
			}
			if _, err := os.Stat(output); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("invalid input started a password process")
			}
		})
	}
}

func TestMariaDBPasswordDeadlineAndErrorsDoNotLeakSQL(t *testing.T) {
	cfg, _ := setupPasswordLiteralProcess(t)
	t.Setenv("OLS_PASSWORD_LITERAL_SLOW", "1")
	mariaDBPasswordTimeout = 100 * time.Millisecond
	start := time.Now()
	err := changeMariaDBPassword("site_user", "fixture-new-secret", cfg)
	if !errors.Is(err, context.DeadlineExceeded) || !errors.Is(err, errMariaDBPasswordOutcomeUnknown) || time.Since(start) > 2*time.Second {
		t.Fatalf("password process did not honor deadline: %v", err)
	}
	t.Setenv("OLS_PASSWORD_LITERAL_SLOW", "0")
	t.Setenv("OLS_PASSWORD_LITERAL_FAIL", "1")
	mariaDBPasswordTimeout = 5 * time.Second
	err = changeMariaDBPassword("site_user", "fixture-new-secret", cfg)
	if !errors.Is(err, errMariaDBPasswordOutcomeUnknown) || strings.Contains(err.Error(), "fixture-new-secret") || strings.Contains(err.Error(), "ALTER USER") {
		t.Fatalf("failed SQL/secret exposed or failure lost: %v", err)
	}
}

func TestWordPressPasswordReplacementEvaluatesToExactRequestedText(t *testing.T) {
	php, err := exec.LookPath("php")
	if err != nil {
		t.Skip("PHP runtime unavailable; generated SQL tests still run")
	}
	cases := []struct{ name, old, password string }{
		{"dollars", "old", "$1 ${name} $$"},
		{"escaped_old_quote", "old\\'password", `new\'"password`},
		{"escaped_old_slash", `old\\password`, `end\`},
		{"unicode_and_newline", "old", "中文🔑\r\nline\n\tend"},
		{"same_password", "unchanged", "unchanged"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			input := []byte("<?php\ndefine('DB_PASSWORD', '" + tc.old + "');\ndefine('OTHER_VALUE', 'untouched');\n")
			result, err := replaceWordPressDBPassword(input, tc.password)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Contains(result, []byte("define('OTHER_VALUE', 'untouched');")) {
				t.Fatal("unrelated config changed")
			}
			path := filepath.Join(t.TempDir(), "wp-config.php")
			if err := os.WriteFile(path, result, 0600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			output, err := exec.CommandContext(ctx, php, "-n", "-r", "require $argv[1]; echo base64_encode(DB_PASSWORD);", path).CombinedOutput()
			if err != nil {
				t.Fatalf("PHP rejected generated config: %v %s", err, output)
			}
			decoded, err := base64.StdEncoding.DecodeString(string(output))
			if err != nil || string(decoded) != tc.password {
				t.Fatalf("PHP password bytes differ: %q %v", decoded, err)
			}
		})
	}
}

func TestExecutePasswordChangeRejectsInvalidTextBeforeConfigMutation(t *testing.T) {
	_, output := setupPasswordLiteralProcess(t)
	root := t.TempDir()
	path := filepath.Join(root, "wp-config.php")
	oldContent := []byte("<?php define('DB_PASSWORD', 'old');\n")
	if err := os.WriteFile(path, oldContent, 0600); err != nil {
		t.Fatal(err)
	}
	for _, password := range []string{"a\x00b", string([]byte{0xff})} {
		result := executeChangeDBPassword(&Task{Payload: &ChangeDBPasswordPayload{Site: &models.Website{DBUser: "site_user", WebRoot: root}, NewPassword: password}})
		if result.Success {
			t.Fatal("invalid text accepted")
		}
		actual, _ := os.ReadFile(path)
		if !bytes.Equal(actual, oldContent) {
			t.Fatal("invalid text modified wp-config")
		}
		if _, err := os.Stat(output); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("invalid text started SQL")
		}
	}
}

func TestExecutePasswordChangePreservesRequestedConfigOnUncertainSQLFailure(t *testing.T) {
	_, output := setupPasswordLiteralProcess(t)
	for _, deadline := range []bool{false, true} {
		t.Run(map[bool]string{false: "client_exit", true: "deadline"}[deadline], func(t *testing.T) {
			t.Setenv("OLS_PASSWORD_LITERAL_FAIL", "1")
			t.Setenv("OLS_PASSWORD_LITERAL_SLOW", "0")
			mariaDBPasswordTimeout = 5 * time.Second
			if deadline {
				t.Setenv("OLS_PASSWORD_LITERAL_SLOW", "1")
				mariaDBPasswordTimeout = 100 * time.Millisecond
			}
			root := t.TempDir()
			path := filepath.Join(root, "wp-config.php")
			oldContent := []byte("<?php define('DB_PASSWORD', 'old\\'password');\n")
			if err := os.WriteFile(path, oldContent, 0600); err != nil {
				t.Fatal(err)
			}
			password := `$1 new\'secret`
			result := executeChangeDBPassword(&Task{Payload: &ChangeDBPasswordPayload{Site: &models.Website{DBUser: "site_user", WebRoot: root}, NewPassword: password}})
			if result.Success || strings.Contains(result.Message, password) || result.Data != nil {
				t.Fatalf("SQL failure misreported/leaked: %+v", result)
			}
			if !deadline {
				if _, err := os.Stat(output); err != nil {
					t.Fatalf("SQL fixture was not reached: %v", err)
				}
			}
			want, err := replaceWordPressDBPassword(oldContent, password)
			if err != nil {
				t.Fatal(err)
			}
			actual, _ := os.ReadFile(path)
			if !strings.Contains(result.Message, "结果未确认") || !strings.Contains(result.Message, "保留新密码") || !bytes.Equal(actual, want) {
				t.Fatal("uncertain SQL claimed success/rollback or lost requested config")
			}
		})
	}
}

func TestExecutePHPPasswordChangeReportsUncertainWithoutConfigOrSecrets(t *testing.T) {
	setupPasswordLiteralProcess(t)
	t.Setenv("OLS_PASSWORD_LITERAL_FAIL", "1")
	result := executeChangeDBPassword(&Task{Payload: &ChangeDBPasswordPayload{Site: &models.Website{DBUser: "site_user", SiteType: "php", WebRoot: t.TempDir()}, NewPassword: "fixture-new-secret"}})
	if result.Success || !strings.Contains(result.Message, "结果未确认") || strings.Contains(result.Message, "fixture-new-secret") || result.Data != nil {
		t.Fatalf("plain PHP uncertain result lost or password leaked: %+v", result)
	}
}

func TestExecutePasswordChangeRestoresConfigWhenClientNeverStarts(t *testing.T) {
	setupPasswordLiteralProcess(t)
	runMariaDBPasswordCommand = func(ctx context.Context, _ string, _ ...string) *exec.Cmd {
		return exec.CommandContext(ctx, filepath.Join(t.TempDir(), "nonexistent-mariadb"))
	}
	root := t.TempDir()
	path := filepath.Join(root, "wp-config.php")
	oldContent := []byte("<?php define('DB_PASSWORD', 'old\\'password');\n")
	if err := os.WriteFile(path, oldContent, 0600); err != nil {
		t.Fatal(err)
	}
	result := executeChangeDBPassword(&Task{Payload: &ChangeDBPasswordPayload{Site: &models.Website{DBUser: "site_user", WebRoot: root}, NewPassword: "$1 new-password"}})
	actual, _ := os.ReadFile(path)
	if result.Success || strings.Contains(result.Message, "结果未确认") || !bytes.Equal(actual, oldContent) {
		t.Fatalf("pre-start failure must restore exact original config: %+v", result)
	}
}
