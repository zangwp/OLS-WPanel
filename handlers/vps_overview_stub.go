//go:build !linux

package handlers

import (
	"os"
	"runtime"

	"github.com/zangwp/OLS-WPanel/executor"
	"github.com/zangwp/OLS-WPanel/models"
)

func collectVPSOverview() VPSOverview {
	hostname, _ := os.Hostname()
	return VPSOverview{
		Identity: VPSIdentity{Hostname: hostname, OS: runtime.GOOS, Architecture: runtime.GOARCH, CPUCores: runtime.NumCPU()},
		Stats:    &models.SystemStats{},
		Tuning:   VPSTuning{Nameservers: []string{}},
		Services: []VPSService{},
		Swap:     executor.SwapStatus{Supported: false, Entries: []executor.SwapEntry{}},
		DNS:      executor.DNSStatus{Supported: false, Current: []string{}, Presets: executor.DNSPresets()},
	}
}
