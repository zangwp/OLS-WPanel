package handlers

import (
	"net/http"

	"github.com/zangwp/OLS-WPanel/internal/executor"
	"github.com/zangwp/OLS-WPanel/internal/models"

	"github.com/gin-gonic/gin"
)

// VPSHandler exposes bounded VPS facts and Swap operations. It never accepts
// arbitrary shell input; every mutation is validated and audited by executor.
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

type swapSettingsRequest struct {
	SizeMB     int64 `json:"size_mb"`
	Swappiness int64 `json:"swappiness"`
}

type swappinessRequest struct {
	Swappiness int64 `json:"swappiness"`
}

type removeSwapRequest struct {
	Confirm string `json:"confirm"`
}

type dnsPresetRequest struct {
	Preset string `json:"preset"`
}

func (h *VPSHandler) SwapStatus(c *gin.Context) {
	status, err := executor.GetSwapStatus()
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse(err.Error()))
		return
	}
	c.JSON(http.StatusOK, models.SuccessResponse(status))
}

func (h *VPSHandler) ApplyRecommendedSwap(c *gin.Context) {
	status, err := executor.ApplyRecommendedSwap()
	if err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse(err.Error()))
		return
	}
	c.JSON(http.StatusOK, models.SuccessResponse(status))
}

func (h *VPSHandler) ApplyCustomSwap(c *gin.Context) {
	var req swapSettingsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("请求参数无效"))
		return
	}
	status, err := executor.ApplyManagedSwap(req.SizeMB, req.Swappiness)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse(err.Error()))
		return
	}
	c.JSON(http.StatusOK, models.SuccessResponse(status))
}

func (h *VPSHandler) SetSwappiness(c *gin.Context) {
	var req swappinessRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("请求参数无效"))
		return
	}
	status, err := executor.SetSwapSwappiness(req.Swappiness)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse(err.Error()))
		return
	}
	c.JSON(http.StatusOK, models.SuccessResponse(status))
}

func (h *VPSHandler) RemoveManagedSwap(c *gin.Context) {
	var req removeSwapRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("请求参数无效"))
		return
	}
	status, err := executor.RemoveManagedSwap(req.Confirm)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse(err.Error()))
		return
	}
	c.JSON(http.StatusOK, models.SuccessResponse(status))
}

func (h *VPSHandler) DNSStatus(c *gin.Context) {
	c.JSON(http.StatusOK, models.SuccessResponse(executor.GetDNSStatus()))
}

func (h *VPSHandler) TestDNSPreset(c *gin.Context) {
	var req dnsPresetRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("请求参数无效"))
		return
	}
	status, err := executor.ProbeDNSPreset(c.Request.Context(), req.Preset)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse(err.Error()))
		return
	}
	c.JSON(http.StatusOK, models.SuccessResponse(status))
}

func (h *VPSHandler) ApplyDNSPreset(c *gin.Context) {
	var req dnsPresetRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("请求参数无效"))
		return
	}
	status, err := executor.ApplyDNSPreset(c.Request.Context(), req.Preset)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse(err.Error()))
		return
	}
	c.JSON(http.StatusOK, models.SuccessResponse(status))
}

func (h *VPSHandler) RestoreAutomaticDNS(c *gin.Context) {
	status, err := executor.RestoreAutomaticDNS(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse(err.Error()))
		return
	}
	c.JSON(http.StatusOK, models.SuccessResponse(status))
}

func (h *VPSHandler) EnableNftablesBoot(c *gin.Context) {
	if err := executor.EnableNftablesBoot(); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse(err.Error()))
		return
	}
	c.JSON(http.StatusOK, models.SuccessResponse(gin.H{"enabled": true}))
}
