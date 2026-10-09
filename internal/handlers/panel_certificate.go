package handlers

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/zangwp/OLS-WPanel/internal/config"
	"github.com/zangwp/OLS-WPanel/internal/database"
	"github.com/zangwp/OLS-WPanel/internal/executor"
	"github.com/zangwp/OLS-WPanel/internal/i18n"
	"github.com/zangwp/OLS-WPanel/internal/models"
)

var panelCertificateJob struct {
	sync.Mutex
	Running      bool
	Error        string
	ErrorCode    string
	ErrorDetails map[string]string
	LastSuccess  string
}

var checkPanelDomainForSettings = executor.CheckPanelDomain
var applyPanelCertificateForSettings = executor.ApplyPanelDomainCertificate
var readPanelTLSStateForSettings = executor.ReadPanelTLSState

func panelCertificateErrorResponse(c *gin.Context, status int, err error) {
	code, details := executor.PanelDomainErrorInfo(err)
	c.JSON(status, gin.H{"success": false, "message": i18n.TE(c.Request, "settings."+code), "error_code": code, "details": details})
}

func (h *SettingsHandler) PanelCertificateStatus(c *gin.Context) {
	cfg := config.AppConfig
	if cfg == nil {
		panelCertificateErrorResponse(c, http.StatusInternalServerError, fmt.Errorf("panel configuration unavailable"))
		return
	}
	state, err := readPanelTLSStateForSettings(cfg.Panel.TLSCertPath)
	if err != nil {
		panelCertificateErrorResponse(c, http.StatusInternalServerError, err)
		return
	}
	port, usesTLS := executor.PanelListenEndpoint(cfg)
	data := gin.H{"domain": state.Domain, "login_url": "", "expires_at": "", "renewal_error": "", "renewal_error_code": "", "renewal_error_details": nil, "port": port, "uses_tls": usesTLS, "certificate_source": ""}
	if state.Domain != "" && port > 0 {
		scheme := "http"
		if usesTLS {
			scheme = "https"
		}
		data["login_url"] = (&url.URL{Scheme: scheme, Host: fmt.Sprintf("%s:%d", state.Domain, port), Path: "/" + cfg.Panel.RandomSuffix}).String()
	}
	if pair, err := executor.GetPanelCertificate(nil); usesTLS && err == nil && len(pair.Certificate) > 0 {
		if leaf, err := x509.ParseCertificate(pair.Certificate[0]); err == nil {
			data["expires_at"] = leaf.NotAfter.UTC().Format(time.RFC3339)
			if state.Domain != "" {
				data["certificate_source"] = "lets_encrypt"
			} else if string(leaf.RawIssuer) == string(leaf.RawSubject) && leaf.CheckSignature(leaf.SignatureAlgorithm, leaf.RawTBSCertificate, leaf.Signature) == nil {
				data["certificate_source"] = "self_signed"
			} else {
				data["certificate_source"] = "custom"
			}
		}
	}
	var renewalError string
	if db := database.GetDB(); db != nil {
		_ = db.QueryRow("SELECT svalue FROM security_settings WHERE skey='panel_certificate_renewal_error'").Scan(&renewalError)
	}
	if renewalError != "" {
		var diagnosis executor.PanelDomainError
		if json.Unmarshal([]byte(renewalError), &diagnosis) != nil || diagnosis.Code == "" {
			diagnosis.Code = "panel_certificate_failed"
		}
		data["renewal_error_code"], data["renewal_error_details"] = diagnosis.Code, diagnosis.Details
		data["renewal_error"] = i18n.TE(c.Request, "settings."+diagnosis.Code)
	}
	panelCertificateJob.Lock()
	data["running"], data["error"], data["last_success"] = panelCertificateJob.Running, panelCertificateJob.Error, panelCertificateJob.LastSuccess
	data["error_code"], data["error_details"] = panelCertificateJob.ErrorCode, panelCertificateJob.ErrorDetails
	if panelCertificateJob.ErrorCode != "" {
		data["error"] = i18n.TE(c.Request, "settings."+panelCertificateJob.ErrorCode)
	} else if panelCertificateJob.Error != "" {
		data["error"] = i18n.TE(c.Request, "settings.panel_certificate_failed")
	}
	panelCertificateJob.Unlock()
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, models.SuccessResponse(data))
}

func (h *SettingsHandler) CheckPanelDomain(c *gin.Context) {
	var req struct {
		Domain string `json:"domain"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		panelCertificateErrorResponse(c, http.StatusBadRequest, &executor.PanelDomainError{Code: "panel_domain_invalid"})
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer cancel()
	if err := checkPanelDomainForSettings(ctx, req.Domain); err != nil {
		panelCertificateErrorResponse(c, http.StatusBadRequest, err)
		return
	}
	c.JSON(http.StatusOK, models.SuccessResponse(gin.H{"verified": true}))
}

func (h *SettingsHandler) ApplyPanelCertificate(c *gin.Context) {
	var req struct {
		Domain string `json:"domain"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		panelCertificateErrorResponse(c, http.StatusBadRequest, &executor.PanelDomainError{Code: "panel_domain_invalid"})
		return
	}
	domain, err := executor.NormalizePanelDomain(req.Domain)
	if err != nil {
		panelCertificateErrorResponse(c, http.StatusBadRequest, err)
		return
	}
	panelCertificateJob.Lock()
	if panelCertificateJob.Running {
		panelCertificateJob.Unlock()
		panelCertificateErrorResponse(c, http.StatusConflict, &executor.PanelDomainError{Code: "panel_certificate_running"})
		return
	}
	panelCertificateJob.Running = true
	panelCertificateJob.Error = ""
	panelCertificateJob.ErrorCode = ""
	panelCertificateJob.ErrorDetails = nil
	panelCertificateJob.Unlock()
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
		err := applyPanelCertificateForSettings(ctx, config.AppConfig, domain)
		panelCertificateJob.Lock()
		defer panelCertificateJob.Unlock()
		panelCertificateJob.Running = false
		if err != nil {
			panelCertificateJob.ErrorCode, panelCertificateJob.ErrorDetails = executor.PanelDomainErrorInfo(err)
		} else {
			panelCertificateJob.LastSuccess = time.Now().UTC().Format(time.RFC3339)
		}
	}()
	c.JSON(http.StatusAccepted, models.SuccessResponse(gin.H{"running": true}))
}
