package models

type WebsiteSecurityCheck struct {
	Key        string `json:"key"`
	State      string `json:"state"`
	Configured *bool  `json:"configured"`
	Effective  *bool  `json:"effective"`
}

type WebsiteSecurityStatus struct {
	SiteID    int                    `json:"site_id"`
	CheckedAt string                 `json:"checked_at"`
	Checks    []WebsiteSecurityCheck `json:"checks"`
}
