package executor

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/zangwp/OLS-WPanel/internal/config"
)

const mariadbHealthCheckTimeout = 5 * time.Second

// MariaDBReady verifies that MariaDB accepts connections after a safe restart.
// Unlike runMySQL, it uses a timeout so an unresponsive service cannot block the panel.
func MariaDBReady(ctx context.Context, cfg *config.Config) error {
	checkCtx, cancel := context.WithTimeout(ctx, mariadbHealthCheckTimeout)
	defer cancel()

	cmd := exec.CommandContext(checkCtx, "mysql", "-u", cfg.MariaDB.RootUser, "-N", "-e", "SELECT 1")
	cmd.Env = append(os.Environ(), "MYSQL_PWD="+cfg.MariaDB.RootPassword)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s", strings.TrimSpace(stderr.String()))
	}
	return nil
}
