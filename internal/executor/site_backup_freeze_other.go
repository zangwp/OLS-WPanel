//go:build !linux

package executor

import (
	"context"
	"errors"
	"github.com/zangwp/OLS-WPanel/internal/models"
)

func validateSiteBackupUserAndFilesystem(context.Context, *models.Website) error {
	return errors.New("整站受控停写仅支持 Linux")
}
func stopSiteBackupUserProcesses(context.Context, *models.Website) error {
	return errors.New("整站受控停写仅支持 Linux")
}
func ensureSiteBackupUserStopped(context.Context, *models.Website) error {
	return errors.New("整站受控停写仅支持 Linux")
}
func mountSiteBackupReadOnly(string) (int, error) {
	return 0, errors.New("整站只读挂载仅支持 Linux")
}
func unmountSiteBackupReadOnly(string, int) error {
	return errors.New("整站只读挂载仅支持 Linux")
}
