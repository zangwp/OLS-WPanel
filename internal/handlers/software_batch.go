package handlers

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/gin-gonic/gin"
	"github.com/zangwp/OLS-WPanel/internal/executor"
	"github.com/zangwp/OLS-WPanel/internal/models"
)

var softwareConfigMu sync.Mutex

func writeSoftwareConfigAtomic(path string, data []byte, mode os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".software-config-*")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if err = f.Chmod(mode); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(name, path)
}

func buildPHPBatchConfig(content string, values map[string]string) (string, error) {
	if len(values) == 0 || len(values) > len(softConfigAllowed["PHP"]) {
		return "", fmt.Errorf("invalid PHP configuration batch")
	}
	keys := make([]string, 0, len(values))
	for key, value := range values {
		if !softConfigAllowed["PHP"][key] || hasLineBreak(value) {
			return "", fmt.Errorf("invalid PHP configuration: %s", key)
		}
		if message := validateSoftwareConfigValue("en-US", "PHP", key, value); message != "" {
			return "", fmt.Errorf("%s: %s", key, message)
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		content = replaceIniValue(content, key, values[key])
	}
	// Validate related sizes against the entire proposed configuration, including unchanged values.
	size := func(key string) (uint64, error) {
		v := strings.ToUpper(strings.TrimSpace(findPHPIniValue(content, key)))
		if v == "" {
			return 0, fmt.Errorf("missing PHP setting: %s", key)
		}
		multiplier := uint64(1)
		switch v[len(v)-1] {
		case 'G':
			multiplier = 1024 * 1024 * 1024
			v = v[:len(v)-1]
		case 'M':
			multiplier = 1024 * 1024
			v = v[:len(v)-1]
		case 'K':
			multiplier = 1024
			v = v[:len(v)-1]
		}
		n, err := strconv.ParseUint(v, 10, 64)
		if err != nil || n > ^uint64(0)/multiplier {
			return 0, fmt.Errorf("invalid PHP size: %s", key)
		}
		return n * multiplier, nil
	}
	post, err := size("post_max_size")
	if err != nil {
		return "", err
	}
	upload, err := size("upload_max_filesize")
	if err != nil {
		return "", err
	}
	if post != 0 && post < upload {
		return "", fmt.Errorf("post_max_size must be at least upload_max_filesize")
	}
	return content, nil
}

func (h *SoftwareHandler) SavePHPBatchConfig(c *gin.Context) {
	var req struct {
		Values map[string]string `json:"values"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse("Invalid configuration"))
		return
	}
	softwareConfigMu.Lock()
	defer softwareConfigMu.Unlock()
	path := softwarePHPRuntimeConfigPath()
	data, err := os.ReadFile(path)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse("Cannot read PHP configuration"))
		return
	}
	next, err := buildPHPBatchConfig(string(data), req.Values)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse(err.Error()))
		return
	}
	if next == string(data) {
		c.JSON(http.StatusOK, models.SuccessResponse(gin.H{"changed": false}))
		return
	}
	info, err := os.Stat(path)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse(err.Error()))
		return
	}
	apply := func(content []byte) error { return writeSoftwareConfigAtomic(path, content, info.Mode().Perm()) }
	if err = apply([]byte(next)); err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse(err.Error()))
		return
	}
	regenerate := false
	for key := range req.Values {
		regenerate = regenerate || phpConfigRequiresVHostRegeneration(key)
	}
	check := executor.OpenLiteSpeedBinaryPath() + " -t"
	if out, e := runSoftwareShellCommand(check); e != nil {
		err = fmt.Errorf("configuration check failed: %s", strings.TrimSpace(string(out)))
	}
	if err == nil {
		if regenerate {
			err = softwareRegenerateAllSitesOLSConfigs()
		} else {
			_, err = runSoftwareShellCommand("systemctl restart lshttpd")
		}
	}
	if err == nil {
		_, err = runSoftwareShellCommand("systemctl is-active --quiet lshttpd")
	}
	if err != nil {
		recoveryErr := apply(data)
		if recoveryErr == nil {
			if regenerate {
				recoveryErr = softwareRegenerateAllSitesOLSConfigs()
			} else {
				_, recoveryErr = runSoftwareShellCommand("systemctl restart lshttpd")
			}
		}
		if recoveryErr == nil {
			_, recoveryErr = runSoftwareShellCommand("systemctl is-active --quiet lshttpd")
		}
		message := "PHP configuration failed; previous configuration restored"
		if recoveryErr != nil {
			message = "PHP configuration and recovery failed; inspect OpenLiteSpeed logs"
		}
		c.JSON(http.StatusInternalServerError, models.ErrorResponse(message))
		return
	}
	c.JSON(http.StatusOK, models.SuccessResponse(gin.H{"changed": true}))
}
