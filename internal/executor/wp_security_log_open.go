package executor

import (
	"fmt"
	"os"
	"path/filepath"
)

type wpSecurityLogParent struct {
	path string
	info os.FileInfo
}

var openWPSecurityLogFile = openWPSecurityLogReadOnly

// openSafeWPSecurityLog rejects special files before opening, verifies every
// parent directory, then confirms the opened inode is the inspected file.
// Linux additionally opens nonblocking and without following the final symlink,
// so replacing a regular file with a FIFO during inspection cannot hang a read.
func openSafeWPSecurityLog(path string, allowed func(string) bool) (*os.File, error) {
	clean := filepath.Clean(path)
	if !filepath.IsAbs(clean) || clean != path || allowed == nil || !allowed(filepath.Dir(clean)) {
		return nil, fmt.Errorf("日志路径不在受支持的独立站点目录中")
	}
	parents := make([]wpSecurityLogParent, 0, 12)
	for current := filepath.Dir(clean); ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil {
			return nil, err
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("日志父目录不是安全普通目录: %s", current)
		}
		// Go loads Windows file IDs lazily. Cache them while this inspected
		// path still names the original directory, before opening the log.
		if !os.SameFile(info, info) {
			return nil, fmt.Errorf("无法确认日志父目录身份")
		}
		parents = append(parents, wpSecurityLogParent{current, info})
		if filepath.Dir(current) == current {
			break
		}
	}
	before, err := os.Lstat(clean)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() {
		return nil, fmt.Errorf("日志来源不是普通文件")
	}
	if !os.SameFile(before, before) {
		return nil, fmt.Errorf("无法确认日志文件身份")
	}
	f, err := openWPSecurityLogFile(clean)
	if err != nil {
		return nil, err
	}
	opened, err := f.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(before, opened) {
		f.Close()
		return nil, fmt.Errorf("打开日志时文件身份发生变化")
	}
	for _, parent := range parents {
		after, err := os.Lstat(parent.path)
		if err != nil || !after.IsDir() || after.Mode()&os.ModeSymlink != 0 || !os.SameFile(parent.info, after) {
			f.Close()
			return nil, fmt.Errorf("打开日志时父目录发生变化")
		}
	}
	return f, nil
}
