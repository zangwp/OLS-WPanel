package executor

import (
	"bytes"
	"context"
	"crypto/rand"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/zangwp/OLS-WPanel/internal/config"
	"github.com/zangwp/OLS-WPanel/internal/models"
)

//go:embed wp_panel_access_inspector.php
var wpPanelAccessInspectorSource string

var wpPanelAccessInspectPHP = runWPPanelAccessInspector

type wpPanelAccessProbe struct {
	Installed             bool     `json:"installed"`
	SiteURL               string   `json:"site_url"`
	LoginURL              string   `json:"login_url"`
	ConflictingPlugins    []string `json:"conflicting_plugins"`
	AuthenticationPlugins []string `json:"authentication_plugins"`
	Administrators        []struct {
		ID          int    `json:"id"`
		Login       string `json:"login"`
		DisplayName string `json:"display_name"`
		Proof       string `json:"proof"`
	} `json:"administrators"`
	PermalinksEnabled bool `json:"permalinks_enabled"`
	CurlUnixAvailable bool `json:"curl_unix_available"`
}

// InspectWPPanelAccess deliberately separates a SHORTINIT installation check
// from the installed-site inspection. WP_INSTALLING skips normal plugins, so
// it must never be used while inspecting a plugin-filtered wp_login_url().
func InspectWPPanelAccess(ctx context.Context, site *models.Website) (WPPanelAccessStatus, error) {
	return inspectWPPanelAccess(ctx, site, "", false)
}

// InspectWPPanelAccessForSettings checks a candidate route in the same normal
// WordPress bootstrap that reads the current plugin-filtered login address.
func InspectWPPanelAccessForSettings(ctx context.Context, site *models.Website, suffix string) (WPPanelAccessStatus, error) {
	if err := ValidateWPPanelAccessSuffix(suffix); err != nil {
		return WPPanelAccessStatus{}, err
	}
	return inspectWPPanelAccess(ctx, site, suffix, false)
}

// InspectWPPanelAccessAfterSettings is only for the writer holding the same
// per-site operation lock after it verified installation before changing the
// named MU plugin/settings. It avoids a redundant SHORTINIT process. Normal
// core still refuses an uninstalled database, which makes the writer rollback.
func InspectWPPanelAccessAfterSettings(ctx context.Context, site *models.Website) (WPPanelAccessStatus, error) {
	return inspectWPPanelAccess(ctx, site, "", true)
}

func inspectWPPanelAccess(ctx context.Context, site *models.Website, candidateSuffix string, installationVerified bool) (WPPanelAccessStatus, error) {
	result := WPPanelAccessStatus{ConflictingPlugins: []string{}, AuthenticationPlugins: []string{}, Administrators: []WPPanelAccessAdministrator{}, AdministratorProofs: map[int]string{}}
	if site == nil || site.SiteType != "wordpress" || site.Status != models.StatusActive {
		return result, wpPanelAccessError("site_unavailable")
	}
	settings, err := ReadWPPanelAccessSettings(site)
	if err != nil {
		return result, err
	}
	result.ManualLoginURL = settings.ManualLoginURL
	result.LoginSuffix = settings.LoginSuffix
	result.SSOEnabled = settings.SSOEnabled
	result.RecoveryFile = filepath.Join(site.WebRoot, "wp-content", "mu-plugins", wpPanelAccessPluginFile)
	scheme := "http"
	if site.SSLEnabled {
		scheme = "https"
	}
	result.InstallURL = scheme + "://" + site.Domain + "/wp-admin/install.php"
	var probe wpPanelAccessProbe
	if !installationVerified {
		if err := wpPanelAccessInspectPHP(ctx, site, settings, "installation", "", &probe); err != nil {
			return result, err
		}
		if !probe.Installed {
			result.ReasonCode = "not_installed"
			return result, nil
		}
	}
	if err := wpPanelAccessInspectPHP(ctx, site, settings, "status", candidateSuffix, &probe); err != nil {
		return result, err
	}
	if !probe.Installed {
		return result, wpPanelAccessError("not_installed")
	}
	result.Installed = probe.Installed
	result.SiteURL = probe.SiteURL
	u, err := url.Parse(probe.SiteURL)
	if err != nil || u.User != nil || !strings.EqualFold(u.Hostname(), site.Domain) || (u.Scheme != "https" && u.Scheme != "http") || (u.Port() != "" && u.Port() != "443" && u.Port() != "80") {
		return result, wpPanelAccessError("invalid_site_url")
	}
	result.InstallationPath = strings.TrimSuffix(u.Path, "/")
	if result.InstallationPath == "/" {
		result.InstallationPath = ""
	}
	result.InstallURL = scheme + "://" + site.Domain + result.InstallationPath + "/wp-admin/install.php"
	// Validate origin/path before exposing a plugin-filtered URL as a link.
	result.DetectedLoginURL, err = ValidateWPPanelAccessURL(site, result.InstallationPath, probe.LoginURL)
	if err != nil {
		return result, err
	}
	result.LoginURL = result.DetectedLoginURL
	result.LoginSource = "native"
	result.ConflictingPlugins = probe.ConflictingPlugins
	if result.ConflictingPlugins == nil {
		result.ConflictingPlugins = []string{}
	}
	result.AuthenticationPlugins = probe.AuthenticationPlugins
	if result.AuthenticationPlugins == nil {
		result.AuthenticationPlugins = []string{}
	}
	result.ExternalLoginControl = len(result.ConflictingPlugins) != 0
	if result.ExternalLoginControl {
		result.LoginSource = "plugin"
	} else if settings.LoginSuffix != "" {
		result.LoginSource = "panel"
	}
	if settings.ManualLoginURL != "" {
		result.LoginURL, err = ValidateWPPanelAccessURL(site, result.InstallationPath, settings.ManualLoginURL)
		if err != nil {
			return result, err
		}
		result.LoginSource = "manual"
	}
	for _, user := range probe.Administrators {
		if user.ID <= 0 || user.Login == "" || len(user.Proof) != 64 {
			return result, wpPanelAccessError("runtime_unavailable")
		}
		result.Administrators = append(result.Administrators, WPPanelAccessAdministrator{user.ID, user.Login, user.DisplayName})
		result.AdministratorProofs[user.ID] = user.Proof
	}
	result.PermalinksEnabled = probe.PermalinksEnabled
	result.CurlUnixAvailable = probe.CurlUnixAvailable
	result.BridgeInstalled = (settings.SSOEnabled || settings.LoginSuffix != "") && WPPanelAccessPluginMatches(site, settings)
	switch {
	case !site.SSLEnabled || u.Scheme != "https":
		result.ReasonCode = "https_required"
	case result.ExternalLoginControl:
		result.ReasonCode = "external_login_control"
	case len(result.AuthenticationPlugins) != 0:
		result.ReasonCode = "authentication_plugin"
	case !probe.CurlUnixAvailable:
		result.ReasonCode = "curl_unavailable"
	case !WPPanelAccessBrokerAvailable():
		result.ReasonCode = "broker_unavailable"
	case !settings.SSOEnabled:
		result.ReasonCode = "sso_disabled"
	case !result.BridgeInstalled:
		result.ReasonCode = "bridge_unavailable"
	case len(result.Administrators) == 0:
		result.ReasonCode = "administrator_not_found"
	default:
		result.SSOAvailable = true
	}
	return result, nil
}

func runWPPanelAccessInspector(ctx context.Context, site *models.Website, settings WPPanelAccessSettings, phase, candidateSuffix string, target *wpPanelAccessProbe) error {
	if config.AppConfig == nil || !IsValidDomain(site.Domain) || site.ID <= 0 || site.DBName == "" || !IsValidWPTablePrefix(site.TablePrefix) {
		return wpPanelAccessError("site_unavailable")
	}
	runner, err := newDefaultWPCorePHPRunner(config.AppConfig.Paths.WWWRoot)
	if err != nil {
		return wpPanelAccessError("runtime_unavailable")
	}
	validated, err := runner.validate(wpCoreUpdateExecution{WebRoot: site.WebRoot, SystemUser: site.SystemUser, PHPVersion: site.PHPVersion})
	if err != nil {
		return wpPanelAccessError("runtime_unavailable")
	}
	payload, err := json.Marshal(struct {
		Root            string `json:"root"`
		Domain          string `json:"domain"`
		DBName          string `json:"db_name"`
		TablePrefix     string `json:"table_prefix"`
		Phase           string `json:"phase"`
		LoginSuffix     string `json:"login_suffix"`
		CandidateSuffix string `json:"candidate_suffix"`
		HTTPS           bool   `json:"https"`
	}{validated.root, site.Domain, site.DBName, site.TablePrefix, phase, settings.LoginSuffix, candidateSuffix, site.SSLEnabled})
	if err != nil {
		return err
	}
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return err
	}
	token := hex.EncodeToString(random)
	source := strings.TrimPrefix(wpPanelAccessGuardsSource, "<?php") + "\n" + strings.TrimPrefix(wpPanelAccessInspectorSource, "<?php")
	args := []string{"-u", validated.user, "--", validated.php, "-d", "open_basedir=" + sitePHPOpenBaseDir(validated.root, site.Domain), "-d", "disable_functions=" + sitePHPDisabledFunctions(), "-d", "allow_url_include=0", "-d", "display_errors=0", "-d", "memory_limit=256M", "-r", source}
	execCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	// Share the existing single-PHP budget with inventory and security runtime
	// checks, so opening several websites cannot spawn many 256M bootstraps.
	lockCtx, cancelLock := context.WithTimeout(execCtx, 2*time.Second)
	err = acquireInventorySlot(lockCtx)
	cancelLock()
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return wpPanelAccessError("runtime_unavailable")
	}
	defer releaseInventorySlot()
	cmd := exec.CommandContext(execCtx, validated.runuser, args...)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C.UTF-8", "LC_ALL=C.UTF-8", "HOME=" + validated.home, "USER=" + validated.user, "LOGNAME=" + validated.user, "TMPDIR=/tmp", "OLS_WPANEL_RUNNER_TOKEN=" + token}
	cmd.Stdin = bytes.NewReader(payload)
	stdout, stderr, protocol := newCountingSink(64<<10, false), newCountingSink(64<<10, false), newCountingSink(64<<10, true)
	cmd.Stdout, cmd.Stderr = stdout, stderr
	readPipe, writePipe, err := os.Pipe()
	if err != nil {
		return err
	}
	defer readPipe.Close()
	cmd.ExtraFiles = []*os.File{writePipe}
	wpInventoryConfigureCommand(cmd)
	if err := cmd.Start(); err != nil {
		writePipe.Close()
		return wpPanelAccessError("runtime_unavailable")
	}
	_ = writePipe.Close()
	done := make(chan error, 1)
	go func() { _, err := io.Copy(protocol, readPipe); done <- err }()
	waitErr := cmd.Wait()
	copyErr := <-done
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if execCtx.Err() != nil {
		return wpPanelAccessError("runtime_unavailable")
	}
	_, outExceeded, _ := stdout.snapshot()
	_, errExceeded, _ := stderr.snapshot()
	_, protocolExceeded, raw := protocol.snapshot()
	if copyErr != nil || outExceeded || errExceeded || protocolExceeded {
		return wpPanelAccessError("runtime_unavailable")
	}
	var envelope wpAdminManagerEnvelope
	if json.Unmarshal(raw, &envelope) != nil || envelope.Token != token || waitErr != nil || !envelope.OK {
		if envelope.Token == token && wpAdminManagerErrorPattern.MatchString(envelope.ErrorCode) {
			return wpPanelAccessError(envelope.ErrorCode)
		}
		return wpPanelAccessError("runtime_unavailable")
	}
	if err := json.Unmarshal(envelope.Data, target); err != nil {
		return errors.New("WordPress login inspector response invalid")
	}
	return nil
}
