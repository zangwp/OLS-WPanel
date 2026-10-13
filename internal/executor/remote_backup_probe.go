package executor

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/zangwp/OLS-WPanel/internal/models"
)

var remoteBackupProbeCommand = exec.CommandContext

// ProbeSSHBackupConnection uses the same saved host identities as uploads.
// accept-new may add a first identity, but a changed identity must remain an error.
func ProbeSSHBackupConnection(ctx context.Context, settings models.RemoteBackupSettings) (string, error) {
	if err := ValidateRemoteBackupSettings(settings.Host, settings.Port, settings.Username, settings.AuthType, settings.RemotePath); err != nil {
		return "", err
	}
	if err := RequireSSHBackupDependencies(settings.AuthType); err != nil {
		return "", fmt.Errorf("%w；请在软件管理中补齐备份工具", err)
	}
	return probeSSHBackupConnection(ctx, settings, "/www/ols-wpanel/remote_backup_known_hosts", "/www/ols-wpanel/remote_backup_key")
}

func probeSSHBackupConnection(ctx context.Context, settings models.RemoteBackupSettings, knownHosts, keyPath string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return "", err
	}
	run := func(input []byte, name string, args ...string) ([]byte, error) {
		cmd := remoteBackupProbeCommand(ctx, name, args...)
		configureBackupCommandCancellation(cmd)
		cmd.Stdin = bytes.NewReader(input)
		if name == "sshpass" {
			cmd.Env = append(os.Environ(), "SSHPASS="+settings.Password)
		}
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		out, err := cmd.Output()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if err != nil {
			out = append(out, stderr.Bytes()...)
		}
		return out, err
	}
	opts := []string{"-o", "UserKnownHostsFile=" + knownHosts, "-o", "StrictHostKeyChecking=accept-new", "-o", "ConnectTimeout=10", "-p", fmt.Sprint(settings.Port)}
	sshOpts := fmt.Sprintf("-o UserKnownHostsFile=%s -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 -p %d", knownHosts, settings.Port)
	name := "ssh"
	if settings.AuthType == "key" {
		if _, err := os.Stat(keyPath); err != nil {
			return "", fmt.Errorf("SSH密钥不存在，请先保存设置生成密钥")
		}
		opts = append([]string{"-i", keyPath, "-o", "BatchMode=yes"}, opts...)
		sshOpts += " -i " + keyPath + " -o BatchMode=yes"
	} else {
		name = "sshpass"
		opts = append([]string{"-e", "ssh"}, opts...)
	}
	out, err := run(nil, name, append(opts, settings.Username+"@"+settings.Host, "echo OLS_WPANEL_OK")...)
	if err != nil {
		return "", fmt.Errorf("连接失败: %s: %w", strings.TrimSpace(string(out)), err)
	}
	if !strings.Contains("\n"+strings.ReplaceAll(strings.TrimSpace(string(out)), "\r\n", "\n")+"\n", "\nOLS_WPANEL_OK\n") {
		return "", fmt.Errorf("连接未返回预期结果")
	}

	tmp, err := os.CreateTemp("", "ols-wpanel-rsync-test-*")
	if err != nil {
		return "", fmt.Errorf("创建测试文件失败: %w", err)
	}
	defer os.Remove(tmp.Name())
	_, writeErr := tmp.WriteString("OLS WPanel rsync test")
	closeErr := tmp.Close()
	if writeErr != nil || closeErr != nil {
		return "", fmt.Errorf("写入测试文件失败")
	}
	args := []string{"-avz", "-e", "ssh " + sshOpts, tmp.Name(), settings.Username + "@" + settings.Host + ":" + settings.RemotePath + "/.ols-wpanel-rsync-test.txt"}
	name = "rsync"
	if settings.AuthType == "password" {
		name = "sshpass"
		args = append([]string{"-e", "rsync"}, args...)
	}
	if out, err = run(nil, name, args...); err != nil {
		return "", fmt.Errorf("rsync 测试失败: %s: %w", strings.TrimSpace(string(out)), err)
	}

	// Read only this target's already trusted keys after both authenticated checks.
	// Do not overwrite known_hosts with unauthenticated ssh-keyscan output.
	host := settings.Host
	if settings.Port != 22 {
		host = fmt.Sprintf("[%s]:%d", host, settings.Port)
	}
	keys, err := run(nil, "ssh-keygen", "-F", host, "-f", knownHosts)
	if err != nil {
		return "", nil // Fingerprint display is optional; connectivity already succeeded.
	}
	fingerprint, err := run(keys, "ssh-keygen", "-lf", "-")
	if err != nil {
		return "", nil
	}
	return strings.TrimSpace(string(fingerprint)), nil
}
