package handlers

import (
	"context"
	"github.com/gin-gonic/gin"
	"github.com/zangwp/OLS-WPanel/executor"
	"github.com/zangwp/OLS-WPanel/models"
	"net/http"
)

func (h *VPSHandler) SimpleTool(c *gin.Context) {
	var req struct {
		Action  string `json:"action"`
		Value   string `json:"value"`
		Confirm string `json:"confirm"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid request"))
		return
	}
	if req.Action != "clean-preview" && req.Confirm != req.Action {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Confirmation required"))
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), executor.SimpleVPSToolTimeout())
	defer cancel()
	out, err := executor.RunSimpleVPSTool(ctx, req.Action, req.Value)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse(err.Error()))
		return
	}
	c.JSON(http.StatusOK, models.SuccessResponse(gin.H{"message": out}))
}
