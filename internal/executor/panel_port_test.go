package executor

import (
	"testing"

	"github.com/zangwp/OLS-WPanel/internal/config"
)

func TestPanelListenEndpointSelectsActualListener(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  *config.Config
		port int
		tls  bool
	}{
		{name: "missing configuration"},
		{name: "HTTP fallback", cfg: &config.Config{Panel: config.PanelConfig{Port: 8080, TLSPort: 8443}}, port: 8080},
		{name: "certificate only", cfg: &config.Config{Panel: config.PanelConfig{Port: 8080, TLSPort: 8443, TLSCertPath: "cert.pem"}}, port: 8080},
		{name: "key only", cfg: &config.Config{Panel: config.PanelConfig{Port: 8080, TLSPort: 8443, TLSKeyPath: "key.pem"}}, port: 8080},
		{name: "custom HTTPS", cfg: &config.Config{Panel: config.PanelConfig{Port: 8080, TLSPort: 49173, TLSCertPath: "cert.pem", TLSKeyPath: "key.pem"}}, port: 49173, tls: true},
		{name: "TLS disabled", cfg: &config.Config{Panel: config.PanelConfig{Port: 8080, TLSCertPath: "cert.pem", TLSKeyPath: "key.pem"}}, port: 8080},
		{name: "invalid HTTP", cfg: &config.Config{Panel: config.PanelConfig{Port: 0, TLSPort: 8443}}},
		{name: "invalid HTTPS", cfg: &config.Config{Panel: config.PanelConfig{Port: 8080, TLSPort: 65536, TLSCertPath: "cert.pem", TLSKeyPath: "key.pem"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			port, usesTLS := PanelListenEndpoint(tc.cfg)
			if port != tc.port || usesTLS != tc.tls {
				t.Fatalf("endpoint = (%d, %t), want (%d, %t)", port, usesTLS, tc.port, tc.tls)
			}
		})
	}
}
