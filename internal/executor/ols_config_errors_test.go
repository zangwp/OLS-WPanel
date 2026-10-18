package executor

import (
	"errors"
	"strings"
	"testing"
)

func TestOLSConfigRecoveryErrorReportsOnlyFailedStages(t *testing.T) {
	applyErr := errors.New("configuration validation failed")
	restoreErr := errors.New("registry write failed")
	reloadErr := errors.New("restored service did not start")
	for _, tc := range []struct {
		name    string
		restore error
		reload  error
	}{
		{name: "recovered"},
		{name: "restore failed", restore: restoreErr},
		{name: "reload failed", reload: reloadErr},
		{name: "both failed", restore: restoreErr, reload: reloadErr},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := olsConfigRecoveryError(applyErr, "旧 OpenLiteSpeed 注册表已恢复",
				olsConfigStageError("恢复旧注册表失败", tc.restore),
				olsConfigStageError("恢复后重载失败", tc.reload))
			if !errors.Is(err, applyErr) {
				t.Fatalf("original application error was lost: %v", err)
			}
			message := err.Error()
			if strings.Contains(message, "<nil>") || strings.Contains(message, "%!") {
				t.Fatalf("error includes a formatting artifact: %s", message)
			}
			for _, stage := range []struct {
				label string
				err   error
			}{
				{label: "恢复旧注册表失败", err: tc.restore},
				{label: "恢复后重载失败", err: tc.reload},
			} {
				if strings.Contains(message, stage.label) != (stage.err != nil) {
					t.Fatalf("incorrect stage result for %s: %s", stage.label, message)
				}
				if stage.err != nil && !errors.Is(err, stage.err) {
					t.Fatalf("recovery cause was lost: %s", message)
				}
			}
			if strings.Contains(message, "旧 OpenLiteSpeed 注册表已恢复") != (tc.restore == nil && tc.reload == nil) {
				t.Fatalf("incorrect recovery completion claim: %s", message)
			}
		})
	}
}

func TestOLSConfigRecoveryErrorPreservesNestedApplicationAndRecoveryFailures(t *testing.T) {
	applyErr := errors.New("site configuration rejected")
	ipv4Err := errors.New("IPv4 fallback rejected")
	restoreErr := errors.New("old vhost restore failed")
	applicationErr := olsConfigRecoveryError(applyErr, "",
		olsConfigStageError("IPv4 配置回退也未通过", ipv4Err))
	err := olsConfigRecoveryError(applicationErr, "旧状态已恢复",
		olsConfigStageError("自动恢复不完整", restoreErr))
	for _, cause := range []error{applyErr, ipv4Err, restoreErr} {
		if !errors.Is(err, cause) || strings.Count(err.Error(), cause.Error()) != 1 {
			t.Fatalf("cause was lost or repeated: %v", err)
		}
	}
	if strings.Contains(err.Error(), "旧状态已恢复") || strings.Contains(err.Error(), "<nil>") {
		t.Fatalf("failed recovery claimed success: %v", err)
	}
}

func TestOLSConfigRecoveryErrorWithoutFailureIsNil(t *testing.T) {
	if err := olsConfigRecoveryError(nil, "旧状态已恢复", olsConfigStageError("恢复失败", nil)); err != nil {
		t.Fatalf("nil causes manufactured a failure: %v", err)
	}
	rollbackErr := errors.New("restore failed")
	err := olsConfigRecoveryError(nil, "旧状态已恢复", olsConfigStageError("恢复失败", rollbackErr))
	if !errors.Is(err, rollbackErr) || strings.Contains(err.Error(), "旧状态已恢复") {
		t.Fatalf("standalone recovery failure was lost: %v", err)
	}
}
