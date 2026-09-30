package models

import "time"

type SecuritySetting struct {
	ID          int       `json:"id"`
	Key         string    `json:"skey"`
	Value       string    `json:"svalue"`
	Description string    `json:"description"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type UpdateSecuritySettingsRequest struct {
	Fail2banMaxRetry *int    `json:"fail2ban_maxretry"`
	Fail2banFindTime *int    `json:"fail2ban_findtime"`
	Fail2banBanTime  *int    `json:"fail2ban_bantime"`
	AutoWhitelist    *bool   `json:"auto_whitelist_enabled"`
	WhitelistIPs     *string `json:"whitelist_ips"`
	SSHWhitelistIPs  *string `json:"ssh_whitelist_ips"`
}

type SecurityServiceStatus struct {
	Active  bool `json:"active"`
	Enabled bool `json:"enabled"`
}

type SecurityTimerStatus struct {
	Active  bool   `json:"active"`
	Enabled bool   `json:"enabled"`
	NextRun string `json:"next_run"`
}

type SecurityRuntimeStatus struct {
	Fail2ban            SecurityServiceStatus `json:"fail2ban"`
	Nftables            SecurityServiceStatus `json:"nftables"`
	WhitelistTimer      SecurityTimerStatus   `json:"whitelist_timer"`
	ActiveBans          int                   `json:"active_bans"`
	OfficialWhitelist   int                   `json:"official_whitelist_count"`
	WebWhitelist        int                   `json:"web_whitelist_count"`
	SSHWhitelist        int                   `json:"ssh_whitelist_count"`
	LastWhitelistUpdate string                `json:"last_whitelist_update"`
	CDNEnabledGroups    int                   `json:"cdn_enabled_groups"`
	CDNProtectedSites   int                   `json:"cdn_protected_sites"`
	CDNInvalidBindings  int                   `json:"cdn_invalid_bindings"`
}

type CDNRealIPGroup struct {
	ID          int       `json:"id"`
	Name        string    `json:"name"`
	Provider    string    `json:"provider"`
	HeaderName  string    `json:"header_name"`
	IPRanges    string    `json:"ip_ranges"`
	Builtin     bool      `json:"builtin"`
	Enabled     bool      `json:"enabled"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type OperationLog struct {
	ID        int       `json:"id"`
	Operation string    `json:"operation"`
	Target    string    `json:"target"`
	Status    string    `json:"status"`
	Message   string    `json:"message"`
	CreatedAt time.Time `json:"created_at"`
}
