//go:build !linux

package executor

import "errors"

func ensureVPSCLIPrivateDirectory(string, bool) error {
	return errors.New("受保护的终端状态需要 Linux")
}
func readVPSCLIPrivateFile(string, int64) ([]byte, error) {
	return nil, errors.New("受保护的终端状态需要 Linux")
}
func writeVPSCLIPrivateFile(string, []byte) error {
	return errors.New("受保护的终端状态需要 Linux")
}
