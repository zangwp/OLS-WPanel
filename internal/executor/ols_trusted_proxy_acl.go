package executor

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

const olsTrustedProxyACLMarker = "# OLS WPanel trusted proxy ACL: "

// OLS reads accessControl.allow, not an arbitrary trusted-ip-list file. Keep
// one allow directive and preserve its original administrator-owned bytes.
// The marker detects later manual edits instead of silently replacing them.
type olsTrustedProxyACLState struct {
	Original string   `json:"original"`
	Added    []string `json:"added"`
	SHA256   string   `json:"sha256"`
}

func readOLSTrustedProxyConfig(path string) ([]byte, os.FileInfo, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("OpenLiteSpeed 配置不是普通文件: %s", path)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, nil, fmt.Errorf("OpenLiteSpeed 配置读取期间发生变化: %s", path)
	}
	data, err := io.ReadAll(io.LimitReader(file, 2*1024*1024+1))
	if err != nil || len(data) > 2*1024*1024 {
		return nil, nil, fmt.Errorf("OpenLiteSpeed 配置无法安全读取: %s: %v", path, err)
	}
	return data, info, nil
}

func applyOLSTrustedProxyRanges(mainPath, managedPath string, ranges []string) error {
	old, metadata, err := readOLSTrustedProxyConfig(mainPath)
	if err != nil {
		return err
	}
	normalized, err := NormalizeCDNRealIPRanges(strings.Join(ranges, "\n"))
	if err != nil {
		return err
	}
	if len(normalized) == 0 && !bytes.Contains(old, []byte(olsTrustedProxyACLMarker)) {
		return nil
	}
	registry, _, err := readOLSTrustedProxyConfig(managedPath)
	if err != nil || !bytes.HasPrefix(registry, []byte("# OLS WPanel managed OpenLiteSpeed registry. DO NOT EDIT.\n")) {
		return fmt.Errorf("无法确认 OpenLiteSpeed 为面板受管配置: %v", err)
	}
	content, err := renderOLSTrustedProxyMainConfig(old, managedPath, normalized)
	if err != nil {
		return err
	}
	if bytes.Equal(old, content) {
		return nil
	}
	// Refuse to replace a file changed by another administrator since inspection.
	current, currentInfo, err := readOLSTrustedProxyConfig(mainPath)
	if err != nil || !os.SameFile(metadata, currentInfo) || !bytes.Equal(current, old) {
		return fmt.Errorf("OpenLiteSpeed 主配置已变化，请刷新后重试")
	}
	if err := writeOLSTrustedProxyConfigAtomic(mainPath, content, metadata); err != nil {
		return fmt.Errorf("写入 OpenLiteSpeed 可信代理 ACL 失败: %w", err)
	}
	if _, applyErr := testAndRestartOpenLiteSpeed(); applyErr != nil {
		if restoreErr := writeOLSTrustedProxyConfigAtomic(mainPath, old, metadata); restoreErr != nil {
			return fmt.Errorf("%v；恢复原 OpenLiteSpeed 主配置失败: %w", applyErr, restoreErr)
		}
		if _, restoreErr := testAndRestartOpenLiteSpeed(); restoreErr != nil {
			return fmt.Errorf("%v；原 OpenLiteSpeed 主配置已恢复，但恢复后检查/重启失败: %w", applyErr, restoreErr)
		}
		return fmt.Errorf("%v；原 OpenLiteSpeed 主配置已恢复", applyErr)
	}
	return nil
}

// A replaced main config must retain the existing lsadm/root ownership as
// well as its permissions. The generic managed-file writer creates root-owned
// files and is inappropriate for administrator-owned server configuration.
func writeOLSTrustedProxyConfigAtomic(path string, data []byte, metadata os.FileInfo) error {
	current, err := os.Lstat(path)
	if err != nil || !current.Mode().IsRegular() {
		return fmt.Errorf("OpenLiteSpeed 主配置不是可替换的普通文件: %v", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".ols-wpanel-trusted-acl-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if runtime.GOOS == "linux" {
		uid, gid, err := fileOwnerIDs(metadata)
		if err != nil {
			return err
		}
		if err := tmp.Chown(uid, gid); err != nil {
			return fmt.Errorf("保留 OpenLiteSpeed 主配置所有者失败: %w", err)
		}
	}
	if err := tmp.Chmod(metadata.Mode().Perm()); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// Only the installer-shaped, unambiguous main configuration is changed. Extra
// root includes can hide another server ACL, so they require manual review.
func renderOLSTrustedProxyMainConfig(old []byte, managedPath string, ranges []string) ([]byte, error) {
	normalized, err := NormalizeCDNRealIPRanges(strings.Join(ranges, "\n"))
	if err != nil {
		return nil, err
	}
	if len(normalized) == 0 && !bytes.Contains(old, []byte(olsTrustedProxyACLMarker)) {
		return append([]byte(nil), old...), nil
	}
	sort.Strings(normalized)
	lines := strings.SplitAfter(string(old), "\n")
	depth, aclCount, includeCount, proxyCount := 0, 0, 0, 0
	aclDepth, allowIndex, markerIndex := -1, -1, -1
	var state olsTrustedProxyACLState
	hasDeny := false
	for index, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, olsTrustedProxyACLMarker) {
			if aclDepth != 1 || depth != 1 || markerIndex >= 0 {
				return nil, fmt.Errorf("OpenLiteSpeed 可信代理 ACL 标记位置不明确")
			}
			if err := json.Unmarshal([]byte(strings.TrimPrefix(trimmed, olsTrustedProxyACLMarker)), &state); err != nil {
				return nil, fmt.Errorf("OpenLiteSpeed 可信代理 ACL 标记已改变，请手动核对")
			}
			markerIndex = index
			continue
		}
		code, _, _ := olsTrustedProxyLineParts(line)
		statement := strings.TrimSpace(code)
		if statement == "" {
			continue
		}
		if strings.ContainsAny(statement, "\\\"'\x00") || strings.Contains(statement, "<<<") {
			return nil, fmt.Errorf("OpenLiteSpeed 主配置包含需手动核对的引用或多行结构")
		}
		fields := strings.Fields(statement)
		name := strings.ToLower(fields[0])
		if depth == 0 && name == "include" {
			includeCount++
			if len(fields) != 2 || filepath.Clean(fields[1]) != filepath.Clean(managedPath) {
				return nil, fmt.Errorf("OpenLiteSpeed 主配置包含非面板受管 include，请手动核对")
			}
		}
		if depth == 0 && name == "useipinproxyheader" {
			proxyCount++
			if len(fields) != 2 || fields[1] != "2" {
				return nil, fmt.Errorf("OpenLiteSpeed 必须使用仅可信代理的真实 IP 模式")
			}
		}
		if depth == 0 && name == "accesscontrol" {
			aclCount++
			if statement != fields[0]+" {" {
				return nil, fmt.Errorf("OpenLiteSpeed 服务器访问控制结构不明确")
			}
			aclDepth = 1
		}
		if aclDepth == 1 && depth == 1 {
			if name == "include" || strings.Contains(statement, "{") {
				return nil, fmt.Errorf("OpenLiteSpeed 服务器 ACL 包含需手动核对的嵌套配置")
			}
			if name == "allow" {
				if allowIndex >= 0 || len(fields) < 2 {
					return nil, fmt.Errorf("OpenLiteSpeed 服务器 allow 配置不唯一")
				}
				allowIndex = index
			}
			if name == "deny" && len(fields) > 1 {
				hasDeny = true
			}
		}
		opens, closes := strings.Count(statement, "{"), strings.Count(statement, "}")
		if opens > 1 || closes > 1 || (opens != 0 && closes != 0) || (opens > 0 && !strings.HasSuffix(statement, "{")) || (closes > 0 && statement != "}") {
			return nil, fmt.Errorf("OpenLiteSpeed 主配置块结构需手动核对")
		}
		depth += opens - closes
		if depth < 0 {
			return nil, fmt.Errorf("OpenLiteSpeed 主配置块结构不完整")
		}
		if aclDepth == 1 && depth == 0 {
			aclDepth = -1
		}
	}
	if depth != 0 || aclCount != 1 || includeCount != 1 || proxyCount != 1 || allowIndex < 0 {
		return nil, fmt.Errorf("无法确认唯一的受管 OpenLiteSpeed 服务器 ACL")
	}
	// OLS selects the most specific ACL match. A trusted subnet can override
	// an existing deny subnet, so preserve that restriction by refusing trust
	// additions/retention when a server deny list requires manual review.
	// Removing our recorded additions only restores the original ACL.
	if hasDeny && len(normalized) > 0 {
		return nil, fmt.Errorf("OpenLiteSpeed 服务器存在 deny 拒绝规则，新增可信代理可能覆盖原限制；请手动核对 ACL")
	}
	original := lines[allowIndex]
	if markerIndex >= 0 {
		expected, err := appendOLSTrustedProxyAllow(state.Original, state.Added)
		if err != nil || olsTrustedProxyLineSHA(expected) != state.SHA256 || expected != original {
			return nil, fmt.Errorf("OpenLiteSpeed 可信代理 allow 行已手动改变，请核对后重试")
		}
		original = state.Original
	}
	code, _, eol := olsTrustedProxyLineParts(original)
	fields := strings.Fields(strings.TrimSpace(code))
	if len(fields) < 2 || !strings.EqualFold(fields[0], "allow") || strings.ContainsAny(code, "{}\\\"'\x00") {
		return nil, fmt.Errorf("OpenLiteSpeed 原服务器 allow 行不明确")
	}
	existing := strings.FieldsFunc(strings.Join(fields[1:], " "), func(r rune) bool { return r == ',' || r == ' ' || r == '\t' })
	seen, all := map[string]bool{}, false
	for _, token := range existing {
		seen[strings.ToLower(token)] = true
		all = all || strings.EqualFold(token, "ALL")
	}
	if !all {
		return nil, fmt.Errorf("OpenLiteSpeed 服务器 ACL 已限制访问，面板不会自动放宽为 ALL")
	}
	var added []string
	for _, ip := range normalized {
		token := ip + "T"
		if !seen[strings.ToLower(token)] {
			added = append(added, token)
			seen[strings.ToLower(token)] = true
		}
	}
	applied, err := appendOLSTrustedProxyAllow(original, added)
	if err != nil {
		return nil, err
	}
	marker := ""
	if len(added) > 0 {
		metadata, err := json.Marshal(olsTrustedProxyACLState{Original: original, Added: added, SHA256: olsTrustedProxyLineSHA(applied)})
		if err != nil {
			return nil, err
		}
		indent := original[:len(original)-len(strings.TrimLeft(original, " \t"))]
		marker = indent + olsTrustedProxyACLMarker + string(metadata) + eol
		if len(marker) > 8190 {
			return nil, fmt.Errorf("OpenLiteSpeed 可信代理 ACL 标记超过安全行长度")
		}
	}
	var out strings.Builder
	for index, line := range lines {
		if index == markerIndex {
			continue
		}
		if index == allowIndex {
			out.WriteString(marker)
			out.WriteString(applied)
		} else {
			out.WriteString(line)
		}
	}
	return []byte(out.String()), nil
}

func olsTrustedProxyLineParts(line string) (code, comment, eol string) {
	if strings.HasSuffix(line, "\r\n") {
		eol, line = "\r\n", strings.TrimSuffix(line, "\r\n")
	} else if strings.HasSuffix(line, "\n") {
		eol, line = "\n", strings.TrimSuffix(line, "\n")
	}
	if index := strings.IndexByte(line, '#'); index >= 0 {
		return line[:index], line[index:], eol
	}
	return line, "", eol
}

func appendOLSTrustedProxyAllow(original string, added []string) (string, error) {
	if len(added) == 0 {
		return original, nil
	}
	for _, token := range added {
		if !strings.HasSuffix(token, "T") || !isValidIPOrCIDR(strings.TrimSuffix(token, "T")) {
			return "", fmt.Errorf("OpenLiteSpeed 可信代理 ACL 标记包含无效网络")
		}
	}
	code, comment, eol := olsTrustedProxyLineParts(original)
	trimmed := strings.TrimRight(code, " \t")
	line := trimmed + ", " + strings.Join(added, ", ") + code[len(trimmed):] + comment + eol
	if len(line) > 8190 {
		return "", fmt.Errorf("OpenLiteSpeed 可信代理 ACL 超过安全行长度")
	}
	return line, nil
}

func olsTrustedProxyLineSHA(line string) string {
	hash := sha256.Sum256([]byte(line))
	return hex.EncodeToString(hash[:])
}
