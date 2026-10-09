package models

type WebsiteSecurityCheck struct {
	Key            string            `json:"key"`
	State          string            `json:"state"`
	Configured     *bool             `json:"configured"`
	Effective      *bool             `json:"effective"`
	ReasonCode     string            `json:"reason_code"`
	EvidenceSource string            `json:"evidence_source,omitempty"`
	EvidenceAt     string            `json:"evidence_at,omitempty"`
	RuntimeReady   *bool             `json:"runtime_ready,omitempty"`
	RecentEventAt  string            `json:"recent_event_at,omitempty"`
	Details        map[string]string `json:"details,omitempty"`
	CanVerify      bool              `json:"can_verify"`
	Action         string            `json:"action,omitempty"`
}

type WebsiteSecurityStatus struct {
	SiteID    int                    `json:"site_id"`
	CheckedAt string                 `json:"checked_at"`
	Checks    []WebsiteSecurityCheck `json:"checks"`
}
