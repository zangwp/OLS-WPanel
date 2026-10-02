package handlers

import (
	"context"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/zangwp/OLS-WPanel/config"
	"github.com/zangwp/OLS-WPanel/database"
	"github.com/zangwp/OLS-WPanel/executor"
	"github.com/zangwp/OLS-WPanel/models"
)

var panelCertificateJob struct {
	sync.Mutex
	Running     bool
	Error       string
	LastSuccess string
}

func (h *SettingsHandler) PanelCertificateStatus(c *gin.Context) {
	cfg := config.AppConfig
	state, err := executor.ReadPanelTLSState(cfg.Panel.TLSCertPath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse(err.Error()))
		return
	}
	data := gin.H{"domain": state.Domain, "login_url": "", "expires_at": "", "renewal_error": ""}
	if state.Domain != "" {
		data["login_url"] = (&url.URL{Scheme: "https", Host: fmt.Sprintf("%s:%d", state.Domain, cfg.Panel.TLSPort), Path: "/" + cfg.Panel.RandomSuffix}).String()
	}
	if pair, err := executor.GetPanelCertificate(nil); err == nil && len(pair.Certificate) > 0 {
		if leaf, err := x509.ParseCertificate(pair.Certificate[0]); err == nil {
			data["expires_at"] = leaf.NotAfter.UTC().Format(time.RFC3339)
		}
	}
	var renewalError string
	_ = database.GetDB().QueryRow("SELECT svalue FROM security_settings WHERE skey='panel_certificate_renewal_error'").Scan(&renewalError)
	data["renewal_error"] = renewalError
	panelCertificateJob.Lock()
	data["running"], data["error"], data["last_success"] = panelCertificateJob.Running, panelCertificateJob.Error, panelCertificateJob.LastSuccess
	panelCertificateJob.Unlock()
	c.JSON(http.StatusOK, models.SuccessResponse(data))
}

func (h *SettingsHandler) CheckPanelDomain(c *gin.Context) {
	var req struct {
		Domain string `json:"domain"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid domain"))
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer cancel()
	if err := executor.CheckPanelDomain(ctx, req.Domain); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse(err.Error()))
		return
	}
	c.JSON(http.StatusOK, models.SuccessResponse(gin.H{"verified": true}))
}

func (h *SettingsHandler) ApplyPanelCertificate(c *gin.Context) {
	var req struct {
		Domain string `json:"domain"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid domain"))
		return
	}
	domain, err := executor.NormalizePanelDomain(req.Domain)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse(err.Error()))
		return
	}
	panelCertificateJob.Lock()
	if panelCertificateJob.Running {
		panelCertificateJob.Unlock()
		c.JSON(http.StatusConflict, models.ErrorResponse("Certificate operation already running"))
		return
	}
	panelCertificateJob.Running = true
	panelCertificateJob.Error = ""
	panelCertificateJob.Unlock()
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
		err := executor.ApplyPanelDomainCertificate(ctx, config.AppConfig, domain)
		panelCertificateJob.Lock()
		defer panelCertificateJob.Unlock()
		panelCertificateJob.Running = false
		if err != nil {
			panelCertificateJob.Error = executor.FriendlySSLError(err)
		} else {
			panelCertificateJob.LastSuccess = time.Now().UTC().Format(time.RFC3339)
		}
	}()
	c.JSON(http.StatusAccepted, models.SuccessResponse(gin.H{"running": true}))
}
