package handlers

import (
	"net/http"

	"github.com/zangwp/OLS-WPanel/internal/executor"
	"github.com/zangwp/OLS-WPanel/internal/models"

	"github.com/gin-gonic/gin"
)

// VPSHandler exposes read-only host facts. System changes belong to the SSH
// maintenance menu, not the web API.
type VPSHandler struct{}

type VPSIdentity struct {
	Addresses      []string `json:"addresses"`
	Uptime         string   `json:"uptime"`
	Hostname       string   `json:"hostname"`
	OS             string   `json:"os"`
	Kernel         string   `json:"kernel"`
	Architecture   string   `json:"architecture"`
	CPUModel       string   `json:"cpu_model"`
	CPUCores       int      `json:"cpu_cores"`
	Virtualization string   `json:"virtualization"`
}

type VPSTuning struct {
	CongestionControl string   `json:"congestion_control"`
	DefaultQDisc      string   `json:"default_qdisc"`
	Nameservers       []string `json:"nameservers"`
	Timezone          string   `json:"timezone"`
	NTPSynchronized   bool     `json:"ntp_synchronized"`
	RebootRequired    bool     `json:"reboot_required"`
}

type VPSService struct {
	Name    string `json:"name"`
	Unit    string `json:"unit"`
	Active  string `json:"active"`
	Enabled string `json:"enabled"`
}

type VPSOverview struct {
	Identity   VPSIdentity               `json:"identity"`
	Stats      *models.SystemStats       `json:"stats"`
	Tuning     VPSTuning                 `json:"tuning"`
	Services   []VPSService              `json:"services"`
	Swap       executor.SwapStatus       `json:"swap"`
	DNS        executor.DNSStatus        `json:"dns"`
	IPPriority executor.IPPriorityStatus `json:"ip_priority"`
}

func (h *VPSHandler) Overview(c *gin.Context) {
	status := collectVPSOverview()
	status.IPPriority = executor.GetIPPriorityStatus()
	c.JSON(http.StatusOK, models.SuccessResponse(status))
}

func (h *VPSHandler) SwapStatus(c *gin.Context) {
	status, err := executor.GetSwapStatus()
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse(err.Error()))
		return
	}
	c.JSON(http.StatusOK, models.SuccessResponse(status))
}

func (h *VPSHandler) DNSStatus(c *gin.Context) {
	c.JSON(http.StatusOK, models.SuccessResponse(executor.GetDNSStatus()))
}
