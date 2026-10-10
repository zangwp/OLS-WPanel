package executor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// This same-boot receipt contains no authorization token. It survives a panel
// restart, while systemd independently retains the scheduled rollback.
var firewallAccessChangePath = "/run/ols-wpanel-access-change.json"

type firewallAccessChangeRecord struct {
	Version        int    `json:"version"`
	ID             string `json:"change_id"`
	State          string `json:"state"`
	PreviousExists bool   `json:"previous_exists"`
	Previous       string `json:"previous"`
}

type firewallAccessChangeStatus struct {
	ID, State, Error string
}

// Protected by portRulesMu, like the receipt and the access transaction.
var completedFirewallAccessChangeID string

func firewallAccessChangeID(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:16])
}

func readFirewallAccessChange() (firewallAccessChangeRecord, error) {
	var record firewallAccessChangeRecord
	info, err := os.Lstat(firewallAccessChangePath)
	if err != nil {
		return record, err
	}
	if !info.Mode().IsRegular() || info.Size() > 1<<20 {
		return record, errors.New("防火墙变更记录不是有效的普通文件")
	}
	file, err := os.Open(firewallAccessChangePath)
	if err != nil {
		return record, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return record, errors.New("防火墙变更记录已变化")
	}
	data, err := io.ReadAll(io.LimitReader(file, (1<<20)+1))
	if err != nil || len(data) > 1<<20 {
		return record, errors.New("无法完整读取防火墙变更记录")
	}
	if json.Unmarshal(data, &record) != nil || record.Version != 1 || len(record.ID) != 32 ||
		(record.State != "pending" && record.State != "confirmed" && record.State != "rolled_back") {
		return record, errors.New("防火墙变更记录格式无效")
	}
	if _, err := hex.DecodeString(record.ID); err != nil {
		return record, errors.New("防火墙变更标识无效")
	}
	if record.PreviousExists != (strings.TrimSpace(record.Previous) != "") {
		return record, errors.New("防火墙原规则快照无效")
	}
	return record, nil
}

func saveFirewallAccessChange(record firewallAccessChangeRecord) error {
	if info, err := os.Lstat(firewallAccessChangePath); err == nil {
		if !info.Mode().IsRegular() {
			return errors.New("防火墙变更记录不是普通文件")
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	if len(data) > 1<<20 {
		return errors.New("防火墙变更记录超出安全大小限制")
	}
	file, err := os.CreateTemp(filepath.Dir(firewallAccessChangePath), ".ols-access-change-*")
	if err != nil {
		return err
	}
	name := file.Name()
	defer os.Remove(name)
	if err = file.Chmod(0600); err == nil {
		_, err = file.Write(append(data, '\n'))
	}
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(name, firewallAccessChangePath)
}

func completeFirewallAccessChange(token string) {
	completedFirewallAccessChangeID = firewallAccessChangeID(token)
	record, err := readFirewallAccessChange()
	if err == nil && record.ID == completedFirewallAccessChangeID {
		record.State = "confirmed"
		err = saveFirewallAccessChange(record)
	} else if err == nil {
		err = errors.New("防火墙变更记录与确认不匹配")
	}
	if err != nil {
		// The rules were already permanently saved. Do not roll back runtime
		// alone and leave a different policy on disk because receipt I/O failed.
		recordOperationLog("firewall_access_receipt", completedFirewallAccessChangeID, "failed", err.Error())
	}
}

// Absence of a running job is established from readable systemd state, rather
// than from is-active's nonzero exit code (which also covers command failures).
func firewallAccessRollbackInactive(ctx context.Context, unit string) (bool, error) {
	output, err := portCommand(ctx, "systemctl", "show", unit,
		"--property=LoadState", "--property=ActiveState", "--property=Result")
	if err != nil {
		return false, fmt.Errorf("无法核对防火墙回退任务: %w", err)
	}
	properties := map[string]string{}
	for _, line := range strings.Split(output, "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if ok {
			if _, exists := properties[key]; exists {
				return false, errors.New("防火墙回退任务状态不完整")
			}
			properties[key] = value
		}
	}
	load, active := properties["LoadState"], properties["ActiveState"]
	if (load != "loaded" && load != "not-found") || active == "" {
		return false, errors.New("防火墙回退任务状态不完整")
	}
	if (load == "not-found" && active != "inactive") ||
		(load == "loaded" && strings.HasSuffix(unit, ".service") && properties["Result"] == "") {
		return false, errors.New("防火墙回退任务状态不完整")
	}
	if active == "failed" || (properties["Result"] != "" && properties["Result"] != "success") {
		return false, errors.New("防火墙回退任务执行失败，请通过 SSH 检查规则")
	}
	if active == "inactive" {
		return true, nil
	}
	if active == "active" || active == "activating" || active == "deactivating" || active == "reloading" || active == "maintenance" {
		return false, nil
	}
	return false, errors.New("无法识别防火墙回退任务状态")
}

func readFirewallAccessRollbackTable(ctx context.Context) (bool, string, error) {
	output, err := portCommand(ctx, "nft", "--json", "--stateless", "list", "tables")
	if err != nil {
		return false, "", fmt.Errorf("无法读取防火墙表清单: %w", err)
	}
	var document struct {
		Nftables *[]json.RawMessage `json:"nftables"`
	}
	if json.Unmarshal([]byte(output), &document) != nil || document.Nftables == nil {
		return false, "", errors.New("防火墙表清单不完整，无法确认原规则已恢复")
	}
	exists := false
	for _, raw := range *document.Nftables {
		var entry map[string]json.RawMessage
		if json.Unmarshal(raw, &entry) != nil || len(entry) != 1 {
			return false, "", errors.New("防火墙表清单条目无效")
		}
		if _, metadata := entry["metainfo"]; metadata {
			continue
		}
		var table struct {
			Family string `json:"family"`
			Name   string `json:"name"`
		}
		if json.Unmarshal(entry["table"], &table) != nil || table.Family == "" || table.Name == "" {
			return false, "", errors.New("防火墙表清单条目不完整")
		}
		if table.Family == "inet" && table.Name == accessTable {
			if exists {
				return false, "", errors.New("防火墙受管表清单重复，无法确认回退")
			}
			exists = true
		}
	}
	if !exists {
		return false, "", nil
	}
	current, err := portCommand(ctx, "nft", "--stateless", "list", "table", "inet", accessTable)
	if err != nil || strings.TrimSpace(current) == "" {
		return true, "", errors.New("无法完整读取防火墙原规则表")
	}
	return true, current, nil
}

func inspectFirewallAccessChange(ctx context.Context) firewallAccessChangeStatus {
	record, err := readFirewallAccessChange()
	if os.IsNotExist(err) {
		return firewallAccessChangeStatus{State: "unknown"}
	}
	status := firewallAccessChangeStatus{ID: record.ID, State: "error"}
	if err != nil {
		status.Error = err.Error()
		return status
	}
	if record.State != "pending" || record.ID == completedFirewallAccessChangeID {
		status.State = record.State
		if record.ID == completedFirewallAccessChangeID {
			status.State = "confirmed"
		}
		return status
	}
	for _, unit := range []string{accessRollbackUnit + ".timer", accessRollbackUnit + ".service"} {
		inactive, err := firewallAccessRollbackInactive(ctx, unit)
		if err != nil {
			status.Error = err.Error()
			return status
		}
		if !inactive {
			status.State = "pending"
			return status
		}
	}
	exists, current, err := readFirewallAccessRollbackTable(ctx)
	if err != nil {
		status.Error = "无法核对防火墙原规则是否恢复: " + err.Error()
		return status
	}
	if exists != record.PreviousExists {
		status.Error = "防火墙原规则尚未恢复，请通过 SSH 检查后重试"
		return status
	}
	if exists && current != record.Previous {
		status.Error = "无法确认防火墙原规则已完整恢复，请通过 SSH 检查后重试"
		return status
	}
	record.State = "rolled_back"
	if err := saveFirewallAccessChange(record); err != nil {
		status.Error = "原规则已恢复，但无法记录恢复结果: " + err.Error()
		return status
	}
	if pendingAccess.token != "" && firewallAccessChangeID(pendingAccess.token) == record.ID {
		pendingAccess.token = ""
	}
	status.State = "rolled_back"
	return status
}
