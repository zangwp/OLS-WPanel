package executor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// This process-local receipt is deliberately not an authorization token. After
// a process restart an unknown receipt cannot prove another client's outcome.
func sshPortChangeID(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:16])
}

func sshRollbackUnitsInactive(ctx context.Context) (bool, error) {
	for _, unit := range []string{sshMoveUnit + ".timer", sshMoveUnit + ".service"} {
		inactive, err := firewallAccessRollbackInactive(ctx, unit)
		if err != nil {
			return false, fmt.Errorf("无法核对 SSH 自动恢复任务: %w", err)
		}
		if !inactive {
			return false, nil
		}
	}
	return true, nil
}

func observeSSHPortChange(ctx context.Context, listeners []FirewallListener, status *SSHPortStatus) error {
	idle, err := sshRollbackUnitsInactive(ctx)
	if err != nil {
		status.Pending = true
		return err
	}
	if !idle {
		status.Pending = true
		if sshMove.Token != "" && sshMove.ChangeID != "" && sshMove.changeState == "pending" {
			status.ChangeState = "pending"
		}
		return nil
	}
	if sshMove.ChangeID == "" {
		return nil
	}
	status.ChangeState, status.Pending = "error", true
	if _, err := os.Stat(filepath.Join(sshMove.dir, "pending")); !os.IsNotExist(err) {
		return errors.New("SSH 变更尚未确认恢复，请保留原连接并检查当前状态")
	}
	current, err := os.ReadFile(sshConfigPath)
	if err != nil {
		return errors.New("无法核对 SSH 配置，恢复状态尚未确认")
	}
	exists, table, err := readFirewallAccessRollbackTable(ctx)
	if err != nil {
		return fmt.Errorf("无法核对 SSH 端口策略恢复状态: %w", err)
	}
	state, port := "rolled_back", sshMove.OldPort
	wantConfig, err := os.ReadFile(filepath.Join(sshMove.dir, "original"))
	if err != nil {
		return errors.New("无法读取原 SSH 配置快照，恢复状态尚未确认")
	}
	restore, err := os.ReadFile(filepath.Join(sshMove.dir, "restore.nft"))
	prefix := "add table inet " + accessTable + "\ndelete table inet " + accessTable + "\n"
	if err != nil || !strings.HasPrefix(string(restore), prefix) || !strings.HasSuffix(string(restore), "\n") {
		return errors.New("无法读取原 SSH 端口策略快照，恢复状态尚未确认")
	}
	wantTable := strings.TrimSuffix(strings.TrimPrefix(string(restore), prefix), "\n")
	if sshMove.changeState == "confirmed" {
		state, port, wantTable = "confirmed", sshMove.NewPort, sshMove.confirmedTable
		wantConfig, err = os.ReadFile(filepath.Join(sshMove.dir, "final"))
		if err != nil || wantTable == "" {
			return errors.New("无法读取已保存的 SSH 变更快照")
		}
	}
	if string(current) != string(wantConfig) || exists != (wantTable != "") || table != wantTable {
		if sshMove.changeState == "confirmed" || sshMove.changeState == "rolled_back" {
			// A completed receipt must not freeze later administrative changes.
			// It no longer proves this client's outcome; the normal strict SSH
			// inspection below decides whether the current endpoint is migratable.
			status.ChangeState, status.Pending = "unknown", false
			return nil
		}
		return errors.New("SSH 配置或端口策略与变更快照不一致，请通过原连接核对")
	}
	if err := validateSSHListenerSet(listeners, port); err != nil {
		if sshMove.changeState == "confirmed" || sshMove.changeState == "rolled_back" {
			status.ChangeState, status.Pending = "unknown", false
			return nil
		}
		return err
	}
	sshMove.changeState = state
	if state == "rolled_back" {
		sshMove.Token = ""
	}
	status.Port, status.ChangeState, status.Pending = port, state, false
	return nil
}

func validateSSHListenerSet(listeners []FirewallListener, port int) error {
	found := false
	for _, listener := range listeners {
		if listener.Protocol != "tcp" {
			continue
		}
		if listener.Port == port && listener.Process == "" {
			return errors.New("无法核对 SSH 端口监听进程，恢复状态尚未确认")
		}
		if strings.Contains(listener.Process, "sshd") {
			if listener.Port != port {
				return errors.New("SSH 仍有其他端口监听，变更状态尚未确认")
			}
			found = true
		}
	}
	if !found {
		return errors.New("未检测到快照对应的 SSH 监听，变更状态尚未确认")
	}
	return nil
}

func abortSSHPortChange(cause error) error {
	// Never permit a retry to finalize an aborted transaction, even when the
	// independent rollback fails and its files must be retained for recovery.
	sshMove.Token, sshMove.changeState = "", "error"
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	output, err := portCommand(ctx, "/bin/sh", filepath.Join(sshMove.dir, "rollback.sh"))
	if err != nil {
		return fmt.Errorf("%v；恢复失败，请通过旧 SSH 会话检查，自动恢复资料已保留: %s", cause, output)
	}
	if err := stopFirewallRollbackUnits(ctx, sshMoveUnit+".timer", sshMoveUnit+".service"); err != nil {
		return fmt.Errorf("%v；已执行 SSH 恢复，但恢复任务状态尚未确认: %w", cause, err)
	}
	return fmt.Errorf("%w；已执行 SSH 恢复，请核对实际状态", cause)
}
