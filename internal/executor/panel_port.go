package executor

import "github.com/zangwp/OLS-WPanel/internal/config"

// PanelListenEndpoint selects the same endpoint for the HTTP server and access
// policy. A configured TLS port alone does not enable TLS: both certificate
// paths are required. Missing or invalid configuration must never guess a port.
func PanelListenEndpoint(cfg *config.Config) (port int, usesTLS bool) {
	if cfg == nil {
		return 0, false
	}
	usesTLS = cfg.Panel.TLSPort > 0 && cfg.Panel.TLSCertPath != "" && cfg.Panel.TLSKeyPath != ""
	port = cfg.Panel.Port
	if usesTLS {
		port = cfg.Panel.TLSPort
	}
	if port < 1 || port > 65535 {
		return 0, false
	}
	return port, usesTLS
}
