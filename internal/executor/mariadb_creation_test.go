package executor

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/zangwp/OLS-WPanel/internal/config"
)

func TestMariaDBCreationProcessHelper(t *testing.T) {
	if os.Getenv("OLS_DB_CREATION_HELPER") != "1" {
		return
	}
	input, err := io.ReadAll(os.Stdin)
	if err != nil {
		os.Exit(2)
	}
	file, err := os.OpenFile(os.Getenv("OLS_DB_CREATION_OUTPUT"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		os.Exit(3)
	}
	if err := json.NewEncoder(file).Encode(passwordCommandReceipt{Args: os.Args[3:], Input: string(input)}); err != nil {
		os.Exit(4)
	}
	_ = file.Close()
	if strings.Contains(string(input), "CREATE USER") && os.Getenv("OLS_DB_CREATION_FAIL") == "1" {
		_, _ = os.Stderr.Write(input)
		os.Exit(42)
	}
	os.Exit(0)
}

func setupMariaDBCreationProcess(t *testing.T) (*config.Config, string) {
	t.Helper()
	old := runMariaDBManagementCommand
	runMariaDBManagementCommand = func(_ string, args ...string) *exec.Cmd {
		return exec.Command(os.Args[0], append([]string{"-test.run=^TestMariaDBCreationProcessHelper$", "--"}, args...)...)
	}
	t.Cleanup(func() { runMariaDBManagementCommand = old })
	t.Setenv("OLS_DB_CREATION_HELPER", "1")
	output := filepath.Join(t.TempDir(), "receipts.jsonl")
	t.Setenv("OLS_DB_CREATION_OUTPUT", output)
	cfg := &config.Config{}
	cfg.MariaDB.RootUser, cfg.MariaDB.RootPassword = "root", "fixture-root-secret"
	return cfg, output
}

func readMariaDBCreationReceipts(t *testing.T, path string) []passwordCommandReceipt {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	decoder := json.NewDecoder(file)
	var receipts []passwordCommandReceipt
	for {
		var receipt passwordCommandReceipt
		if err := decoder.Decode(&receipt); errors.Is(err, io.EOF) {
			return receipts
		} else if err != nil {
			t.Fatal(err)
		}
		receipts = append(receipts, receipt)
	}
}

func TestMariaDBCreationKeepsPasswordOutOfArgvAndPreservesLiteralInput(t *testing.T) {
	for _, password := range []string{"fixture-site-secret", `quote'and\slash`, "中文🔑\n\\! echo unsafe\n$1"} {
		t.Run(password, func(t *testing.T) {
			cfg, output := setupMariaDBCreationProcess(t)
			if err := createMariaDBDatabase("site_db", "site_user", password, cfg); err != nil {
				t.Fatal(err)
			}
			receipts := readMariaDBCreationReceipts(t, output)
			if len(receipts) != 5 {
				t.Fatalf("database/user/grant steps changed: %d", len(receipts))
			}
			for _, receipt := range receipts {
				argv := strings.Join(receipt.Args, "\n")
				if strings.Contains(argv, password) || strings.Contains(argv, cfg.MariaDB.RootPassword) || strings.Contains(argv, "IDENTIFIED BY") {
					t.Fatalf("credential-bearing SQL leaked to command arguments: %q", receipt.Args)
				}
			}
			want := "SET SESSION sql_mode='NO_BACKSLASH_ESCAPES';\nCREATE USER 'site_user'@'localhost' IDENTIFIED BY '" + strings.ReplaceAll(password, "'", "''") + "';\n"
			if receipts[2].Input != want || !reflect.DeepEqual(receipts[2].Args, databaseImportClientArgs("root")) {
				t.Fatalf("password literal/client protection changed: %#v", receipts[2])
			}
			if !strings.Contains(strings.Join(receipts[3].Args, " "), "GRANT ALL PRIVILEGES ON `site\\_db`.* TO 'site_user'@'localhost'") {
				t.Fatal("selected schema grant changed")
			}
		})
	}
}

func TestMariaDBCreationFailureDoesNotExposeCredentialSQL(t *testing.T) {
	for _, migration := range []bool{false, true} {
		t.Run(map[bool]string{false: "website", true: "migration"}[migration], func(t *testing.T) {
			cfg, output := setupMariaDBCreationProcess(t)
			t.Setenv("OLS_DB_CREATION_FAIL", "1")
			password := strings.Repeat("secret", 4)
			var err error
			wantCommands := 3
			if migration {
				err = createMigrationMariaDBDatabase("site_db", "site_user", password, cfg)
				wantCommands = 1
			} else {
				err = createMariaDBDatabase("site_db", "site_user", password, cfg)
			}
			if err == nil || strings.Contains(err.Error(), password) || strings.Contains(err.Error(), "IDENTIFIED BY") || strings.Contains(err.Error(), "CREATE USER") {
				t.Fatalf("creation failure was hidden or exposed SQL: %v", err)
			}
			if len(readMariaDBCreationReceipts(t, output)) != wantCommands {
				t.Fatal("creation continued after a failed account statement")
			}
		})
	}
}

func TestMariaDBCreationRejectsInvalidPasswordBeforeChangingDatabase(t *testing.T) {
	for _, password := range []string{"nul\x00password", string([]byte{'a', 0xff})} {
		cfg, output := setupMariaDBCreationProcess(t)
		if err := createMariaDBDatabase("site_db", "site_user", password, cfg); err == nil {
			t.Fatal("invalid text accepted")
		}
		if _, err := os.Stat(output); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("invalid password started a database command")
		}
	}
}
