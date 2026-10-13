package executor

import (
	"fmt"
	"os/exec"
	"strings"
	"testing"
)

func TestSSHVerificationCommandSupportsRootWithoutSudo(t *testing.T) {
	shell, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("POSIX shell is not available")
	}
	for _, uid := range []string{"0", "1000"} {
		t.Run(uid, func(t *testing.T) {
			// Stub every command: this checks shell expansion without executing
			// the verification script, changing user, or contacting an SSH host.
			fixture := fmt.Sprintf(`id() { printf '%%s' '%s'; }
env() { printf 'arg=<%%s>\n' "$@"; }
sudo() { printf 'sudo\n'; "$@"; }
SSH_CONNECTION='192.0.2.10 43111 192.0.2.20 2222'
`, uid)
			script := "/run/ols-ssh-port-fixture/quote ' and space/verify.sh"
			out, err := exec.Command(shell, "-c", fixture+sshVerificationCommand(script, "test-token")).CombinedOutput()
			if err != nil {
				t.Fatalf("verification command failed: %v: %s", err, out)
			}
			want := "arg=<OLS_SSH_CONNECTION=192.0.2.10 43111 192.0.2.20 2222>\narg=</bin/sh>\narg=<" + script + ">\narg=<test-token>\n"
			if uid != "0" {
				want = "sudo\n" + want
			}
			if got := strings.ReplaceAll(string(out), "\r\n", "\n"); got != want {
				t.Fatalf("verification command arguments = %q, want %q", got, want)
			}
		})
	}
}
