package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"github.com/gin-gonic/gin"
	"github.com/zangwp/OLS-WPanel/internal/config"
	"github.com/zangwp/OLS-WPanel/internal/middleware"
	"github.com/zangwp/OLS-WPanel/internal/models"
	"golang.org/x/crypto/bcrypt"
)

// Replace the complete credential pair in one write; a partial write must never
// leave the gateway username changed while retaining an unintended password.
func writeAccountConfig(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".account-config-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(0600); err != nil {
		f.Close()
		return err
	}
	if _, err = f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}

func (h *SettingsHandler) updateBasicAuthAccount(c *gin.Context, req settingsUpdateRequest) bool {
	fail := func(message string) bool {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse(message))
		return false
	}
	if h.Auth == nil || h.Auth.Audit == nil || config.AppConfig == nil {
		return fail("账户安全服务暂不可用")
	}
	original, err := os.ReadFile(h.configPath())
	if err != nil {
		return fail("读取配置文件失败")
	}
	var document map[string]json.RawMessage
	if err = json.Unmarshal(original, &document); err != nil {
		return fail("解析配置文件失败")
	}
	var basic map[string]any
	if err = json.Unmarshal(document["basic_auth"], &basic); err != nil || basic == nil {
		return fail("读取入口认证配置失败")
	}
	if req.BasicAuthUser != nil && *req.BasicAuthUser != "" {
		basic["username"] = *req.BasicAuthUser
	}
	if req.BasicAuthPw != nil && *req.BasicAuthPw != "" {
		hash, hashErr := bcrypt.GenerateFromPassword([]byte(*req.BasicAuthPw), 12)
		if hashErr != nil {
			return fail("密码加密失败")
		}
		basic["password_hash"] = string(hash)
	}
	document["basic_auth"], err = json.Marshal(basic)
	if err != nil {
		return fail("序列化入口认证配置失败")
	}
	updated, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return fail("序列化配置失败")
	}
	username, usernameOK := basic["username"].(string)
	hash, hashOK := basic["password_hash"].(string)
	if !usernameOK || !hashOK || username == "" || hash == "" {
		return fail("入口认证配置格式无效")
	}
	tx, err := h.Auth.DB.BeginTx(c.Request.Context(), nil)
	if err != nil {
		return fail("启动账户更新失败")
	}
	defer tx.Rollback()
	if _, err = h.Auth.Audit.RecordTx(c.Request.Context(), tx, requestAuditEvent(c, c.GetString("session_username"), "credentials_changed")); err != nil {
		return fail("安全审计暂不可用，凭据未更改")
	}
	if err = writeAccountConfig(h.configPath(), updated); err != nil {
		log.Printf("account configuration write failed: %v", err)
		return fail("写入入口认证配置失败")
	}
	if err = tx.Commit(); err != nil {
		if rollbackErr := writeAccountConfig(h.configPath(), original); rollbackErr != nil {
			// Keep live and on-disk credentials aligned when filesystem recovery fails.
			config.AppConfig.BasicAuth.Username, _ = basic["username"].(string)
			config.AppConfig.BasicAuth.PasswordHash, _ = basic["password_hash"].(string)
			log.Printf("account configuration rollback failed: %v", rollbackErr)
			return fail("凭据已更改，但审计提交及配置回滚失败，请检查面板日志")
		}
		return fail("审计提交失败，入口认证配置已恢复")
	}
	config.AppConfig.BasicAuth.Username = username
	config.AppConfig.BasicAuth.PasswordHash = hash
	token, _ := c.Cookie("wp_session")
	middleware.GlobalSessionStore.DeleteOthers(c.GetString("session_username"), token)
	h.Auth.dispatchSecurityNotifications(c)
	return true
}
