package main

import (
	"errors"
	"strings"
	"testing"
)

func TestVPSCLIAuditDistinguishesHostFailureFromOutputFailure(t *testing.T) {
	for _, outcome := range []string{"success", "pending", "started"} {
		status, message := vpsCLIAuditResult(true, errors.New("broken pipe"), outcome, "主机操作已有结果")
		if status != outcome || !strings.Contains(message, "操作已执行") || !strings.Contains(message, "输出失败") {
			t.Fatalf("completed %s changed to a host failure: %s %s", outcome, status, message)
		}
	}
	status, message := vpsCLIAuditResult(false, errors.New("swapon failed"), "success", "")
	if status != "failed" || message != "swapon failed" {
		t.Fatalf("actual host failure hidden: %s %s", status, message)
	}
	status, message = vpsCLIAuditResult(true, nil, "pending", "等待新 SSH 连接确认")
	if status != "pending" || message != "等待新 SSH 连接确认" {
		t.Fatalf("pending transaction was described as finalized: %s %s", status, message)
	}
}
