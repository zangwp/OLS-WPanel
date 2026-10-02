//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestWPAnomalyRunnerQueryUsesExistingIsolation(t *testing.T) {
	runner, fixture := newTestInventoryRunner(t, []byte("<?php // fixture"))
	openBase := sitePHPRunnerOpenBaseDir(fixture.site.WebRoot, fixture.site.Domain, filepath.Join(runner.runnerRoot, runner.hash))
	body := validSuccessEnvelopeBody(fixture.uid, fixture.gid, openBase)
	script := fmt.Sprintf("#!/bin/sh\nprintf '%%s' \"$OLS_WPANEL_ANOMALY_QUERY\" > %q\nprintf 'OLS_WPANEL_INVENTORY_BEGIN %%s\\n%%s\\nOLS_WPANEL_INVENTORY_END %%s\\n' \"$OLS_WPANEL_RUNNER_TOKEN\" %q \"$OLS_WPANEL_RUNNER_TOKEN\" >&3\n", fixture.auditPath, body)
	if err := os.Chmod(runner.runuserPath, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(runner.runuserPath, []byte(script), 0555); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OLS_WPANEL_ANOMALY_QUERY", "untrusted-parent-query")
	if _, err := runner.Collect(context.Background(), fixture.cfg, fixture.site, false); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(fixture.auditPath)
	if len(raw) != 0 {
		t.Fatal("ordinary scan inherited anomaly query")
	}
	runner.anomalyQuery = &wpAnomalyQuery{Since: 100, Until: 200, KnownIDs: []int{1}}
	if _, err := runner.Collect(context.Background(), fixture.cfg, fixture.site, false); err != nil {
		t.Fatal(err)
	}
	raw, _ = os.ReadFile(fixture.auditPath)
	var got wpAnomalyQuery
	if err := json.Unmarshal(raw, &got); err != nil || got.Since != 100 || got.Until != 200 || len(got.KnownIDs) != 1 {
		t.Fatal(string(raw), err)
	}
}

func TestWPAnomalyRunnerDoesNotRequireOptimizer(t *testing.T) {
	php, err := exec.LookPath("php")
	if err != nil {
		t.Skip("php not installed")
	}
	source := string(wpInventoryRunnerSource)
	start := strings.Index(source, "function ols_wpanel_inventory_collect_anomaly(")
	end := strings.Index(source[start:], "\n$token =")
	if start < 0 || end < 0 {
		t.Fatal("missing native sampler")
	}
	fn := source[start : start+end]
	for _, multi := range []bool{false, true} {
		harness := fmt.Sprintf(`function is_multisite(){return %t;} define('OLS_WPANEL_INVENTORY_RUNNER',true); echo ols_wpanel_inventory_anomaly_sample(['since'=>-1,'until'=>2,'known_ids'=>[]])['error'];`, multi)
		output, err := exec.Command(php, "-r", fn+harness).CombinedOutput()
		want := "sample_invalid"
		if multi {
			want = "multisite_unsupported"
		}
		if err != nil || string(output) != want {
			t.Fatal(string(output), err)
		}
	}
}

func TestOptimizerRetirementDoesNotInheritParentPermission(t *testing.T) {
	runner, fixture := newTestInventoryRunner(t, []byte("<?php // fixture"))
	openBase := sitePHPRunnerOpenBaseDir(fixture.site.WebRoot, fixture.site.Domain, filepath.Join(runner.runnerRoot, runner.hash))
	body := validSuccessEnvelopeBody(fixture.uid, fixture.gid, openBase)
	script := fmt.Sprintf("#!/bin/sh\nprintf '%%s' \"$OLS_WPANEL_RETIRE_OPTIMIZER\" > %q\nprintf 'OLS_WPANEL_INVENTORY_BEGIN %%s\\n%%s\\nOLS_WPANEL_INVENTORY_END %%s\\n' \"$OLS_WPANEL_RUNNER_TOKEN\" %q \"$OLS_WPANEL_RUNNER_TOKEN\" >&3\n", fixture.auditPath, body)
	if err := os.WriteFile(runner.runuserPath, []byte(script), 0555); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OLS_WPANEL_RETIRE_OPTIMIZER", "1")
	if _, err := runner.Collect(context.Background(), fixture.cfg, fixture.site, false); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(fixture.auditPath)
	if len(raw) != 0 {
		t.Fatal("read-only inventory inherited mutation permission")
	}
	runner.retireOptimizer = true
	if _, err := runner.Collect(context.Background(), fixture.cfg, fixture.site, false); err != nil {
		t.Fatal(err)
	}
	raw, _ = os.ReadFile(fixture.auditPath)
	if string(raw) != "1" {
		t.Fatal("explicit retirement permission missing")
	}
}
