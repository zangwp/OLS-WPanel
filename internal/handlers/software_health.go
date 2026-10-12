package handlers

import (
	"context"
	"errors"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/zangwp/OLS-WPanel/internal/executor"
	"github.com/zangwp/OLS-WPanel/internal/i18n"
	"github.com/zangwp/OLS-WPanel/internal/models"
)

var (
	softwareHealthRuntimeList   = executor.ListLSPHPRuntimesContext
	softwareHealthRuntimeRead   = executor.ReadLSPHPRuntimeHealthWithProbe
	softwareHealthBackupRead    = executor.ReadBackupDependencyHealth
	softwareHealthBackupInstall = executor.InstallBackupDependencies
)

// Health is read-only. It reuses bounded, coalesced command probes, and does
// not add cron to the service guard or change any website/PHP configuration.
func (h *SoftwareHandler) Health(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()
	fresh := c.Query("fresh") == "1"
	runtimes := softwareHealthRuntimeList(ctx)
	php := make([]executor.LSPHPRuntimeHealth, len(runtimes))
	var cron softwareCronHealth
	var backup executor.BackupDependencyHealth
	var loading sync.WaitGroup
	probe := func(ctx context.Context, name string, args ...string) ([]byte, error) {
		out, err := softwareReadCache.read(ctx, fresh, name, args...)
		return []byte(out), err
	}
	for index, runtime := range runtimes {
		loading.Add(1)
		go func(index int, runtime executor.LSPHPRuntime) {
			defer loading.Done()
			php[index] = softwareHealthRuntimeRead(ctx, runtime, probe)
		}(index, runtime)
	}
	loading.Add(2)
	go func() {
		defer loading.Done()
		cron = getCronHealth(ctx, fresh)
	}()
	go func() {
		defer loading.Done()
		backup = softwareHealthBackupRead(ctx)
	}()
	loading.Wait()
	c.JSON(http.StatusOK, models.SuccessResponse(gin.H{
		"php": php, "backup": backup, "cron": cron,
		"checked_at": time.Now().UTC().Format(time.RFC3339),
	}))
}

func (h *SoftwareHandler) InstallBackupDependencies(c *gin.Context) {
	// Browser cancellation must not interrupt a package-manager transaction.
	// The fixed executor allowlist installs only missing, required tools.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	health, err := softwareHealthBackupInstall(ctx)
	softwareReadCache.invalidate()
	if err != nil {
		if errors.Is(err, executor.ErrBackupDependencyInstallBusy) {
			c.JSON(http.StatusConflict, models.ErrorResponse(i18n.T(softwareLang(c), "software.backup_dependencies_install_busy")))
			return
		}
		log.Printf("安装备份依赖失败: %v", err)
		c.JSON(http.StatusInternalServerError, models.ErrorResponse(i18n.T(softwareLang(c), "software.backup_dependencies_install_failed")))
		return
	}
	c.JSON(http.StatusOK, models.SuccessResponse(gin.H{
		"backup":  health,
		"message": i18n.T(softwareLang(c), "software.backup_dependencies_installed"),
	}))
}
