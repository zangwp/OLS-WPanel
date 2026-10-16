package executor

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

const redisHealthCheckTimeout = 5 * time.Second

// RedisReady verifies that Redis responds to PING. The panel changes only
// maxmemory, so probe the package's default 127.0.0.1:6379 listener. Update
// this probe if the panel gains bind or port settings.
func RedisReady(ctx context.Context) error {
	checkCtx, cancel := context.WithTimeout(ctx, redisHealthCheckTimeout)
	defer cancel()

	out, execErr := exec.CommandContext(checkCtx, "redis-cli", "-h", "127.0.0.1", "-p", "6379", "ping").CombinedOutput()
	resp := strings.TrimSpace(string(out))

	switch {
	case resp == "PONG":
		return nil
	case strings.Contains(resp, "NOAUTH"):
		// Admins may set requirepass outside the panel. NOAUTH still proves Redis
		// can process requests; accept it as ready so missing credentials do not
		// cause every config save to roll back.
		return nil
	case execErr != nil:
		return fmt.Errorf("%s", resp)
	default:
		return fmt.Errorf("unexpected response: %s", resp)
	}
}
