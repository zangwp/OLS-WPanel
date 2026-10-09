package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/zangwp/OLS-WPanel/internal/database"
	"github.com/zangwp/OLS-WPanel/internal/executor"
	"github.com/zangwp/OLS-WPanel/internal/i18n"
	"github.com/zangwp/OLS-WPanel/internal/models"
)

var verifySiteSecurityForHandler = executor.VerifyWebsiteSecurityStatus
var siteSecurityVerificationLimit = struct {
	sync.Mutex
	next map[int]time.Time
}{next: make(map[int]time.Time)}

func allowSiteSecurityVerification(siteID int, now time.Time) bool {
	siteSecurityVerificationLimit.Lock()
	defer siteSecurityVerificationLimit.Unlock()
	for id, deadline := range siteSecurityVerificationLimit.next {
		if !now.Before(deadline) {
			delete(siteSecurityVerificationLimit.next, id)
		}
	}
	if deadline, exists := siteSecurityVerificationLimit.next[siteID]; exists && now.Before(deadline) {
		return false
	}
	if len(siteSecurityVerificationLimit.next) >= 1024 {
		return false
	}
	siteSecurityVerificationLimit.next[siteID] = now.Add(3 * time.Second)
	return true
}

func siteSecurityVerificationError(c *gin.Context, status int, code string) {
	c.JSON(status, gin.H{"success": false, "error_code": code, "message": i18n.TE(c.Request, "site_security."+code)})
}

// Register only on the authenticated, CSRF-protected group. This POST explicitly
// authorizes a bounded diagnostic; it never changes policies or sends attacks.
func (h *WebsiteHandler) VerifySecurityStatus(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil || id <= 0 {
		siteSecurityVerificationError(c, http.StatusBadRequest, "invalid_request")
		return
	}
	var request struct {
		Key string `json:"key"`
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 1024)
	decoder := json.NewDecoder(c.Request.Body)
	decoder.DisallowUnknownFields()
	if decoder.Decode(&request) != nil || !executor.WebsiteSecurityCheckVerifiable(request.Key) {
		siteSecurityVerificationError(c, http.StatusBadRequest, "invalid_request")
		return
	}
	var trailing interface{}
	if err := decoder.Decode(&trailing); err != io.EOF {
		siteSecurityVerificationError(c, http.StatusBadRequest, "invalid_request")
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 12*time.Second)
	defer cancel()
	db := database.GetDB()
	if db == nil {
		siteSecurityVerificationError(c, http.StatusServiceUnavailable, "data_unavailable")
		return
	}
	site, err := scanWebsite(db.QueryRowContext(ctx, "SELECT "+websiteCols+" FROM websites WHERE id=?", id).Scan)
	if errors.Is(err, sql.ErrNoRows) {
		siteSecurityVerificationError(c, http.StatusNotFound, "site_not_found")
		return
	}
	if err != nil {
		siteSecurityVerificationError(c, http.StatusServiceUnavailable, "data_unavailable")
		return
	}
	if site.Status != models.StatusActive {
		siteSecurityVerificationError(c, http.StatusConflict, "site_not_active")
		return
	}
	if !allowSiteSecurityVerification(id, time.Now()) {
		c.Header("Retry-After", "3")
		siteSecurityVerificationError(c, http.StatusTooManyRequests, "rate_limited")
		return
	}
	if !executor.TryAcquireSiteOpLock(id, "security-verification") {
		siteSecurityVerificationError(c, http.StatusConflict, "site_busy")
		return
	}
	defer executor.ReleaseSiteOpLock(id)
	report, err := verifySiteSecurityForHandler(ctx, site, request.Key)
	if err != nil || report.SiteID != site.ID || len(report.Checks) == 0 {
		siteSecurityVerificationError(c, http.StatusServiceUnavailable, "verification_failed")
		return
	}
	completeWebsiteSecuritySettings(ctx, db, site, &report)
	c.JSON(http.StatusOK, models.SuccessResponse(report))
}
