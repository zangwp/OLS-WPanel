package middleware

import (
	"io/fs"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// VersionedStaticCache caches only existing public assets with the exact build
// version. HTML, API responses, missing files and unversioned URLs are excluded.
func VersionedStaticCache(prefix, version string, files fs.FS) gin.HandlerFunc {
	return func(c *gin.Context) {
		if version != "" && version != "dev" && c.Query("v") == version &&
			(c.Request.Method == http.MethodGet || c.Request.Method == http.MethodHead) &&
			strings.HasPrefix(c.Request.URL.Path, prefix+"/") {
			name := strings.TrimPrefix(c.Request.URL.Path, prefix+"/")
			if fs.ValidPath(name) && files != nil {
				if info, err := fs.Stat(files, name); err == nil && !info.IsDir() {
					c.Header("Cache-Control", "public, max-age=31536000, immutable")
				}
			}
		}
		c.Next()
	}
}
