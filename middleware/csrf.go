package middleware

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"net/http"

	"github.com/gin-gonic/gin"
)

const csrfTokenLength = 32

func generateCSRFToken() (string, error) {
	b := make([]byte, csrfTokenLength)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func CSRF() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.Method == http.MethodGet || c.Request.Method == http.MethodHead || c.Request.Method == http.MethodOptions {
			c.Next()
			return
		}

		headerToken := c.GetHeader("X-CSRF-Token")
		if headerToken == "" {
			headerToken = c.GetHeader("X-Csrf-Token")
		}

		cookieToken, err := c.Cookie("csrf_token")
		if err != nil || cookieToken == "" {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"success": false,
				"message": "CSRF token 缺失",
			})
			return
		}

		if subtle.ConstantTimeCompare([]byte(headerToken), []byte(cookieToken)) != 1 {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"success": false,
				"message": "CSRF token 不匹配",
			})
			return
		}

		c.Next()
	}
}

func SetCSRFToken(c *gin.Context) bool {
	token, err := c.Cookie("csrf_token")
	if err != nil || token == "" {
		token, err = generateCSRFToken()
		if err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
				"success": false,
				"message": "无法生成安全令牌",
			})
			return false
		}
		http.SetCookie(c.Writer, &http.Cookie{
			Name:     "csrf_token",
			Value:    token,
			MaxAge:   86400,
			Path:     "/",
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteLaxMode,
		})
	}
	c.Set("csrf_token", token)
	c.Header("X-CSRF-Token", token)
	return true
}

func GetCSRFToken(c *gin.Context) string {
	t, _ := c.Get("csrf_token")
	if s, ok := t.(string); ok {
		return s
	}
	return ""
}
