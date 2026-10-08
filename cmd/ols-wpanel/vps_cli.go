package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/zangwp/OLS-WPanel/internal/config"
	"github.com/zangwp/OLS-WPanel/internal/database"
	"github.com/zangwp/OLS-WPanel/internal/executor"
	"github.com/zangwp/OLS-WPanel/internal/handlers"
)

func vpsCLIMutates(action string) bool {
	switch action {
	case "swap-recommended", "swap-custom", "swap-swappiness", "swap-remove",
		"dns", "dns-custom", "time-sync", "system-update", "clean", "ip-priority",
		"tuning", "locale", "locale-install", "timezone", "hostname", "ssh-port-start", "ssh-port-confirm":
		return true
	}
	return false
}

func vpsCLIAuditResult(completed bool, operationErr error, outcome, message string) (string, string) {
	if operationErr == nil {
		return outcome, message
	}
	if !completed {
		return "failed", operationErr.Error()
	}
	return outcome, message + "；操作已执行，但结果输出失败：" + operationErr.Error()
}

// This path never creates a database or runs daemon initialization. Host
// maintenance remains usable when SQLite is missing; workload counts then
// explicitly remain unknown and the independent terminal history is retained.
func runVPSCLI(cfg *config.Config, action, value string) (operationErr error) {
	if strings.HasPrefix(action, "swap-") {
		if err := executor.ValidateSwapCLI(action, value); err != nil {
			return err
		}
	}
	if executor.IsVPSMaintenanceCLI(action) {
		if err := executor.ValidateVPSMaintenanceCLI(action, value, cfg); err != nil {
			return err
		}
	}
	mutates := vpsCLIMutates(action)
	if mutates && os.Geteuid() != 0 {
		return fmt.Errorf("终端维护修改需要 root 权限")
	}
	if !mutates && !executor.IsVPSMaintenanceCLI(action) {
		switch action {
		case "swap-status", "dns-status", "dns-test", "dns-custom-test", "system-update-status", "clean-preview", "cli-audit":
		default:
			return fmt.Errorf("未知终端维护操作")
		}
	}
	if mutates || action == "swap-status" || action == "ports-status" {
		if err := database.OpenExisting(cfg.SQLite.Path, !mutates); err != nil {
			fmt.Fprintf(os.Stderr, "面板数据库暂不可用：%v；将使用独立终端记录，Swap 站点数量与受管规则可能未知。\n", err)
		} else {
			defer database.Close()
		}
	}
	outcome, message, completed := "success", "终端维护操作已完成", false
	if mutates {
		defer func() {
			outcome, message = vpsCLIAuditResult(completed, operationErr, outcome, message)
			if err := executor.AuditVPSCLI(action, value, outcome, message); err != nil {
				fmt.Fprintf(os.Stderr, "维护记录未保存：%v；上述操作结果不变。\n", err)
			}
		}()
	}
	ctx, cancel := context.WithTimeout(context.Background(), executor.SimpleVPSToolTimeout())
	defer cancel()
	encode := func(result any) error { return json.NewEncoder(os.Stdout).Encode(result) }
	if strings.HasPrefix(action, "swap-") {
		status, err := executor.RunSwapCLI(action, value)
		if err != nil {
			return err
		}
		completed = true
		return encode(status)
	}
	if executor.IsVPSMaintenanceCLI(action) {
		result, err := executor.RunVPSMaintenanceCLI(ctx, action, value, cfg)
		if err != nil {
			return err
		}
		if action == "ssh-port-start" {
			outcome, message = "pending", "双端口过渡已启动，等待新 SSH 连接确认；超时自动恢复"
		}
		completed = true
		return encode(result)
	}
	switch action {
	case "cli-audit":
		auditAction, auditStatus, ok := strings.Cut(value, ":")
		if !ok || (auditStatus != "success" && auditStatus != "failed") {
			return fmt.Errorf("终端维护记录参数无效")
		}
		switch auditAction {
		case "restart", "update", "repair", "password", "unban":
			return executor.AuditVPSCLI(auditAction, "", auditStatus, "面板终端操作："+auditStatus)
		default:
			return fmt.Errorf("不支持记录此面板终端操作")
		}
	case "dns-status", "dns-test", "dns-custom-test":
		status := executor.GetDNSStatus()
		var err error
		if action == "dns-test" {
			status, err = executor.ProbeDNSPreset(ctx, value)
		} else if action == "dns-custom-test" {
			status, err = executor.ProbeCustomDNS(ctx, value)
		}
		if writeErr := encode(status); writeErr != nil {
			return writeErr
		}
		return err
	case "dns", "dns-custom":
		var err error
		if action == "dns-custom" {
			_, err = executor.ApplyCustomDNS(ctx, value)
		} else if value == "default" {
			_, err = executor.RestoreAutomaticDNS(ctx)
		} else {
			_, err = executor.ApplyDNSPreset(ctx, value)
		}
		if err != nil {
			return err
		}
		completed = true
		_, err = fmt.Fprintln(os.Stdout, "DNS 配置已更新并核对。")
		return err
	case "time-sync":
		if err := handlers.StartSystemTimeSync(); err != nil {
			return err
		}
		completed = true
		_, err := fmt.Fprintln(os.Stdout, "自动校时已启动；是否已同步请查看当前状态。")
		return err
	case "system-update":
		status, err := executor.StartSystemPackageUpdate(cfg)
		if err != nil {
			return err
		}
		outcome, message = "started", "后台系统更新已启动，任务 "+status.ID
		completed = true
		_, err = fmt.Fprintf(os.Stdout, "系统更新已启动: %s\n使用 o system-update-status 查看进度。\n", status.ID)
		return err
	case "system-update-status":
		return encode(executor.ReconcileSystemPackageUpdateStatus(cfg))
	}
	out, err := executor.RunSimpleVPSTool(ctx, action, value)
	if err != nil {
		return err
	}
	completed = true
	_, err = fmt.Fprintln(os.Stdout, out)
	return err
}
