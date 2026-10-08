package executor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type vpsCLISSHState struct {
	Change         SSHPortChange `json:"change"`
	Directory      string        `json:"directory"`
	Service        string        `json:"service"`
	ExpectedConfig string        `json:"expected_config"`
	ExpectedTable  string        `json:"expected_table"`
}

type vpsCLISSHStartResult struct {
	SSHPortChange
	ConfirmCommand string `json:"confirm_command"`
}

type vpsCLISSHConfirmResult struct {
	Status  string `json:"status"`
	NewPort int    `json:"new_port"`
	Message string `json:"message"`
}

func beginVPSCLISSHChange(port int, clientIP string) (vpsCLISSHStartResult, error) {
	if os.Geteuid() != 0 {
		return vpsCLISSHStartResult{}, errors.New("修改 SSH 端口需要 root 权限")
	}
	return beginVPSCLISSHChangeWithStorage(vpsCLIStateDirectory, port, clientIP, productionVPSCLIStorage())
}

func beginVPSCLISSHChangeWithStorage(stateDir string, port int, clientIP string, storage vpsCLIStorage) (vpsCLISSHStartResult, error) {
	if err := storage.ensureDirectory(stateDir, true); err != nil {
		return vpsCLISSHStartResult{}, err
	}
	lock, err := storage.lock(filepath.Join(stateDir, "ssh.lock"))
	if err != nil {
		return vpsCLISSHStartResult{}, err
	}
	defer lock.Close()
	// The shared transaction checks its single systemd rollback unit before
	// editing files. That unit also excludes web-initiated SSH transactions;
	// the CLI lock additionally serializes separate terminal invocations.
	change, err := BeginSSHPortChange(port, clientIP)
	if err != nil {
		return vpsCLISSHStartResult{}, err
	}
	portRulesMu.Lock()
	state := vpsCLISSHState{Change: sshMove.SSHPortChange, Directory: sshMove.dir, Service: sshMove.service, ExpectedConfig: sshMove.expectedConfig, ExpectedTable: sshMove.expectedTable}
	portRulesMu.Unlock()
	data, err := json.Marshal(state)
	if err == nil && len(data) > 512*1024 {
		err = errors.New("SSH 事务状态超过大小上限")
	}
	if err == nil {
		err = storage.writeFile(filepath.Join(stateDir, "ssh-pending.json"), data)
	}
	if err != nil {
		// The existing systemd watchdog is independent of this short-lived CLI
		// process. Do not stop it when the cross-process snapshot cannot be saved.
		return vpsCLISSHStartResult{}, fmt.Errorf("SSH 新旧端口暂时保留，但确认状态保存失败；自动恢复任务仍有效，请保持原连接并等待恢复: %w", err)
	}
	return vpsCLISSHStartResult{SSHPortChange: change, ConfirmCommand: "o ssh-confirm " + change.Token}, nil
}

func validateVPSCLISSHState(state vpsCLISSHState, token, connection string, now time.Time) error {
	if !vpsCLISSHtokenRE.MatchString(token) || state.Change.Token != token || now.After(state.Change.Deadline) || state.Change.Deadline.After(now.Add(5*time.Minute)) {
		return errors.New("SSH 变更已过期或令牌无效；请保持原连接，等待自动恢复")
	}
	if state.Change.OldPort < 1 || state.Change.OldPort > 65535 || state.Change.NewPort < 1 || state.Change.NewPort > 65535 || state.Change.NewPort == state.Change.OldPort {
		return errors.New("保存的 SSH 端口状态无效")
	}
	if filepath.Clean(state.Directory) != state.Directory || filepath.Dir(state.Directory) != filepath.Clean(sshMoveRunDirectory) || !strings.HasPrefix(filepath.Base(state.Directory), "ols-ssh-port-") {
		return errors.New("SSH 事务目录身份无效")
	}
	if state.Service != "ssh.service" && state.Service != "sshd.service" {
		return errors.New("SSH 事务服务无效")
	}
	if state.ExpectedConfig == "" || state.ExpectedTable == "" {
		return errors.New("SSH 事务快照不完整")
	}
	return validateVPSCLISSHConnection(connection, state.Change.NewPort)
}

func confirmVPSCLISSHChange(token, connection string) (vpsCLISSHConfirmResult, error) {
	if os.Geteuid() != 0 {
		return vpsCLISSHConfirmResult{}, errors.New("确认 SSH 端口需要 root 权限")
	}
	return confirmVPSCLISSHChangeWithStorage(vpsCLIStateDirectory, token, connection, productionVPSCLIStorage())
}

func confirmVPSCLISSHChangeWithStorage(stateDir, token, connection string, storage vpsCLIStorage) (vpsCLISSHConfirmResult, error) {
	if err := storage.ensureDirectory(stateDir, false); err != nil {
		return vpsCLISSHConfirmResult{}, err
	}
	lock, err := storage.lock(filepath.Join(stateDir, "ssh.lock"))
	if err != nil {
		return vpsCLISSHConfirmResult{}, err
	}
	defer lock.Close()
	statePath := filepath.Join(stateDir, "ssh-pending.json")
	data, err := storage.readFile(statePath, 512*1024)
	if err != nil {
		return vpsCLISSHConfirmResult{}, fmt.Errorf("无法读取待确认 SSH 事务；未移除旧端口: %w", err)
	}
	var state vpsCLISSHState
	if err = json.Unmarshal(data, &state); err != nil {
		return vpsCLISSHConfirmResult{}, errors.New("SSH 确认状态格式无效，未移除旧端口")
	}
	if err = validateVPSCLISSHState(state, token, connection, time.Now()); err != nil {
		return vpsCLISSHConfirmResult{}, err
	}
	if err = storage.ensureDirectory(state.Directory, false); err != nil {
		return vpsCLISSHConfirmResult{}, err
	}
	pending, err := storage.readFile(filepath.Join(state.Directory, "pending"), 128)
	if err != nil || string(pending) != token {
		return vpsCLISSHConfirmResult{}, errors.New("SSH 事务已恢复或不再待确认，未移除旧端口")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	if !cliSSHWatchdogActive(ctx) {
		return vpsCLISSHConfirmResult{}, errors.New("SSH 自动恢复任务已停止，未移除旧端口；请检查当前配置")
	}
	// Prove the current connection uses the new port, then hand finalization to
	// the original implementation. Its configuration/table checks, listener
	// retirement, Fail2ban migration, persistence and rollback remain intact.
	if err = storage.writeFile(filepath.Join(state.Directory, "verified"), []byte(token)); err != nil {
		return vpsCLISSHConfirmResult{}, err
	}
	portRulesMu.Lock()
	sshMove.SSHPortChange = state.Change
	sshMove.dir, sshMove.service = state.Directory, state.Service
	sshMove.expectedConfig, sshMove.expectedTable = state.ExpectedConfig, state.ExpectedTable
	portRulesMu.Unlock()
	if err = ConfirmSSHPortChange(token); err != nil {
		return vpsCLISSHConfirmResult{}, err
	}
	// A completed transaction clears its own pending marker. Removing the
	// snapshot is housekeeping; never turn successful finalization into a retry.
	_ = os.Remove(statePath)
	return vpsCLISSHConfirmResult{Status: "success", NewPort: state.Change.NewPort, Message: "新 SSH 端口已确认并保存，旧端口已移除：" + strconv.Itoa(state.Change.NewPort)}, nil
}

// cliSSHWatchdogActive is deliberately read-only and shared with tests that
// verify the adapter never attempts confirmation without the original timer.
func cliSSHWatchdogActive(ctx context.Context) bool { return sshMoveActive(ctx) }
