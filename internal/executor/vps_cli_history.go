package executor

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const vpsCLIStateDirectory = "/var/lib/ols-wpanel/vps-cli"
const vpsCLIHistoryLimit = 200
const vpsCLIHistoryMaxBytes = 256 * 1024

type VPSCLIHistoryEntry struct {
	At      time.Time `json:"at"`
	Action  string    `json:"action"`
	Value   string    `json:"value"`
	Status  string    `json:"status"`
	Message string    `json:"message"`
}

// AuditVPSCLI records terminal maintenance independently of SQLite. An audit
// failure is returned separately: callers must not report a completed host
// change as unexecuted merely because recording it failed.
func AuditVPSCLI(action, value, status, message string) error {
	if os.Geteuid() != 0 {
		return errors.New("终端维护记录需要 root 权限")
	}
	entry, err := normalizeVPSCLIAudit(action, value, status, message)
	if err != nil {
		return err
	}
	if err := appendVPSCLIHistory(vpsCLIStateDirectory, entry); err != nil {
		return fmt.Errorf("终端维护历史记录失败: %w", err)
	}
	// Mirror only when main already opened the existing database. This helper
	// never opens or creates a database as a side effect of recording history.
	recordOperationLog("vps_cli_"+entry.Action, entry.Value, entry.Status, entry.Message)
	return nil
}

var vpsCLIAuditSecretRE = regexp.MustCompile(`(?i)(password|passwd|token|secret|密码|令牌)\s*[:=]\s*[^\s,;]+`)
var vpsCLIAuditTokenRE = regexp.MustCompile(`[a-fA-F0-9]{48,}`)

func normalizeVPSCLIAudit(action, value, status, message string) (VPSCLIHistoryEntry, error) {
	entry := VPSCLIHistoryEntry{At: time.Now().UTC(), Action: action, Status: status}
	switch status {
	case "success", "failed", "pending", "started", "cancelled":
	default:
		return entry, errors.New("无效的终端维护结果状态")
	}
	// Values use an allowlist rather than accepting arbitrary command output.
	// SSH confirmation tokens, client addresses, credentials and shell input
	// never become targets in history or in the optional SQLite mirror.
	switch action {
	case "ssh-port-start":
		if port, _, err := parseVPSCLISSHStart(value); err == nil {
			entry.Value = strconv.Itoa(port)
		}
		entry.Message = "SSH 端口变更：" + status
	case "ssh-port-confirm":
		entry.Message = "新 SSH 连接确认：" + status
	case "dns", "dns-test":
		if value == "international" || value == "mainland_china" || value == "default" {
			entry.Value = value
		}
	case "dns-custom":
		addresses := strings.FieldsFunc(value, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == '\t' })
		valid := len(addresses) > 0 && len(addresses) <= 8
		for index, address := range addresses {
			ip := net.ParseIP(address)
			if ip == nil {
				valid = false
				break
			}
			addresses[index] = ip.String()
		}
		if valid {
			entry.Value = strings.Join(addresses, ",")
		}
	case "ip-priority":
		if value == "ipv4" || value == "ipv6" || value == "default" {
			entry.Value = value
		}
	case "tuning":
		if value == "balanced" || value == "website" || value == "default" {
			entry.Value = value
		}
	case "timezone":
		if len(value) <= 128 && regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_+/-]*$`).MatchString(value) && !strings.Contains(value, "..") {
			entry.Value = value
		}
	case "hostname":
		if len(value) > 0 && len(value) <= 253 && regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.-]*$`).MatchString(value) && !strings.Contains(value, "..") {
			entry.Value = value
		}
	case "locale", "locale-install":
		if value == "en_US.UTF-8" || value == "zh_CN.UTF-8" || value == "zh_TW.UTF-8" {
			entry.Value = value
		}
	case "swap-custom", "swap-swappiness":
		if _, err := parseSwapCLIRequest(action, value); err == nil {
			entry.Value = value
		}
	case "swap-remove":
		entry.Value = "managed-file"
	case "swap-recommended", "time-sync", "clean", "system-update", "restart", "update", "repair", "unban":
	case "password":
		entry.Message = "账户维护：" + status
	default:
		return entry, errors.New("不支持记录此终端维护操作")
	}
	if entry.Message == "" {
		message = vpsCLIAuditSecretRE.ReplaceAllString(message, "[已隐藏敏感值]")
		message = vpsCLIAuditTokenRE.ReplaceAllString(message, "[已隐藏令牌]")
		entry.Message = strings.ReplaceAll(sanitizeVPSCLIText(message, 300), "\n", " ")
	}
	return entry, nil
}

func decodeVPSCLIHistory(data []byte) ([]VPSCLIHistoryEntry, error) {
	entries := []VPSCLIHistoryEntry{}
	if len(data) > vpsCLIHistoryMaxBytes {
		return nil, errors.New("历史文件超过大小上限")
	}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		if len(bytes.TrimSpace(scanner.Bytes())) == 0 {
			continue
		}
		var entry VPSCLIHistoryEntry
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			return nil, errors.New("历史文件格式无效，未覆盖原记录")
		}
		entries = append(entries, entry)
		if len(entries) > vpsCLIHistoryLimit {
			entries = entries[1:]
		}
	}
	return entries, scanner.Err()
}

func appendVPSCLIHistory(dir string, entry VPSCLIHistoryEntry) error {
	return appendVPSCLIHistoryWithStorage(dir, entry, productionVPSCLIStorage())
}

func appendVPSCLIHistoryWithStorage(dir string, entry VPSCLIHistoryEntry, storage vpsCLIStorage) error {
	if err := storage.ensureDirectory(dir, true); err != nil {
		return err
	}
	lock, err := storage.lock(filepath.Join(dir, "history.lock"))
	if err != nil {
		return err
	}
	defer lock.Close()
	path := filepath.Join(dir, "history.jsonl")
	data, err := storage.readFile(path, vpsCLIHistoryMaxBytes)
	if errors.Is(err, os.ErrNotExist) {
		data, err = nil, nil
	}
	if err != nil {
		return err
	}
	entries, err := decodeVPSCLIHistory(data)
	if err != nil {
		return err
	}
	entries = append(entries, entry)
	if len(entries) > vpsCLIHistoryLimit {
		entries = entries[len(entries)-vpsCLIHistoryLimit:]
	}
	var out bytes.Buffer
	for {
		out.Reset()
		encoder := json.NewEncoder(&out)
		for _, item := range entries {
			if err := encoder.Encode(item); err != nil {
				return err
			}
		}
		if out.Len() <= vpsCLIHistoryMaxBytes {
			break
		}
		if len(entries) <= 1 {
			return errors.New("单条历史记录超过大小上限")
		}
		// Unicode error messages can consume several bytes per character.
		// Retain the latest records instead of permanently wedging the log
		// when its byte bound is reached before its row bound.
		entries = entries[1:]
	}
	return storage.writeFile(path, out.Bytes())
}

func readVPSCLIHistory(dir string) ([]VPSCLIHistoryEntry, error) {
	return readVPSCLIHistoryWithStorage(dir, productionVPSCLIStorage())
}

func readVPSCLIHistoryWithStorage(dir string, storage vpsCLIStorage) ([]VPSCLIHistoryEntry, error) {
	if err := storage.ensureDirectory(dir, false); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return []VPSCLIHistoryEntry{}, nil
		}
		return nil, err
	}
	data, err := storage.readFile(filepath.Join(dir, "history.jsonl"), vpsCLIHistoryMaxBytes)
	if errors.Is(err, os.ErrNotExist) {
		return []VPSCLIHistoryEntry{}, nil
	}
	if err != nil {
		return nil, err
	}
	entries, err := decodeVPSCLIHistory(data)
	for left, right := 0, len(entries)-1; left < right; left, right = left+1, right-1 {
		entries[left], entries[right] = entries[right], entries[left]
	}
	return entries, err
}
