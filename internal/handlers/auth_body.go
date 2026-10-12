package handlers

import (
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

const accountRequestBodyTimeout = 10 * time.Second

// Authentication bodies are small. Bound their read separately from uploads,
// and finish parsing before taking the account mutation lock.
func bindAccountRequest(c *gin.Context, value interface{}) error {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 4096)
	controller := http.NewResponseController(c.Writer)
	if err := controller.SetReadDeadline(time.Now().Add(accountRequestBodyTimeout)); err != nil && !errors.Is(err, http.ErrNotSupported) {
		return err
	}
	defer controller.SetReadDeadline(time.Time{})
	return c.ShouldBindJSON(value)
}
