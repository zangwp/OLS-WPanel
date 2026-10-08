//go:build !linux

package executor

import (
	"errors"
	"os"
)

func dnsFileOwner() (int, int) { return 0, 0 }
func openDNSStatusFile(path string) (*os.File, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("DNS 状态来源不是普通文件")
	}
	return os.Open(path)
}
func readDNSFileSnapshot(string, bool) (dnsFileSnapshot, error) {
	return dnsFileSnapshot{}, errors.New("DNS 文件设置仅支持 Linux")
}
func writeDNSFileSnapshotAtomic(string, dnsFileSnapshot) error {
	return errors.New("DNS 文件设置仅支持 Linux")
}
func ensureDNSPrivateDirectory(string, bool) error {
	return errors.New("DNS 管理备份仅支持 Linux")
}
func acquireDNSManagerLock(string) (func(), error) {
	return nil, errors.New("DNS 管理锁仅支持 Linux")
}
