package handlers

import (
	"bytes"
	"errors"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

const (
	pluginRequestBodyLimit   = 64 << 10
	pluginRequestBodyTimeout = 10 * time.Second
)

// PluginRequestGuard applies the existing loopback boundary before any JSON or
// maintenance lookup. Site-specific API key authentication remains in handlers.
// These plugin calls carry small JSON, never panel uploads or backup streams.
func PluginRequestGuard() gin.HandlerFunc {
	return pluginRequestGuard(pluginRequestBodyTimeout)
}

func pluginRequestGuard(timeout time.Duration) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Cache-Control", "no-store")
		controller := http.NewResponseController(c.Writer)
		reject := func(status int, message string) {
			// Do not let net/http drain an unread slow body after sending an error.
			c.Request.Close = true
			c.Header("Connection", "close")
			_ = controller.SetReadDeadline(time.Now())
			c.AbortWithStatusJSON(status, gin.H{"success": false, "message": message})
		}
		key := c.GetHeader("X-OLS-WPanel-Key")
		if !pluginRequestHostAllowed(c) || key == "" || len(key) > 256 {
			reject(http.StatusUnauthorized, "API Key 无效")
			return
		}
		if c.Request.Body == nil || c.Request.Body == http.NoBody {
			c.Next()
			return
		}
		if c.Request.ContentLength > pluginRequestBodyLimit {
			reject(http.StatusRequestEntityTooLarge, "请求内容过大")
			return
		}
		if err := controller.SetReadDeadline(time.Now().Add(timeout)); err != nil {
			reject(http.StatusServiceUnavailable, "暂时无法读取请求")
			return
		}
		original := c.Request.Body
		data, err := io.ReadAll(http.MaxBytesReader(c.Writer, original, pluginRequestBodyLimit))
		if err != nil {
			var tooLarge *http.MaxBytesError
			var networkError net.Error
			switch {
			case errors.As(err, &tooLarge):
				reject(http.StatusRequestEntityTooLarge, "请求内容过大")
			case errors.As(err, &networkError) && networkError.Timeout():
				reject(http.StatusRequestTimeout, "读取请求超时")
			default:
				reject(http.StatusBadRequest, "参数错误")
			}
			return
		}
		if err := controller.SetReadDeadline(time.Time{}); err != nil {
			reject(http.StatusServiceUnavailable, "暂时无法读取请求")
			return
		}
		_ = original.Close()
		c.Request.Body = io.NopCloser(bytes.NewReader(data))
		c.Next()
	}
}
