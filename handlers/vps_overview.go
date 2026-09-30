package handlers

import (
	"net/http"

	"github.com/zangwp/OLS-WPanel/models"

	"github.com/gin-gonic/gin"
)

// VPSHandler exposes read-only host facts used by the VPS management page.
// Mutating operations intentionally remain in the existing, audited settings,
// firewall and software workflows instead of accepting arbitrary shell input.
type VPSHandler struct{}

type VPSIdentity struct {
	Hostname       string `json:"hostname"`
	OS             string `json:"os"`
	Kernel         string `json:"kernel"`
	Architecture   string `json:"architecture"`
	CPUModel       string `json:"cpu_model"`
	CPUCores       int    `json:"cpu_cores"`
	Virtualization string `json:"virtualization"`
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
	Identity VPSIdentity         `json:"identity"`
	Stats    *models.SystemStats `json:"stats"`
	Tuning   VPSTuning           `json:"tuning"`
	Services []VPSService        `json:"services"`
}

func (h *VPSHandler) Overview(c *gin.Context) {
	c.JSON(http.StatusOK, models.SuccessResponse(collectVPSOverview()))
}
