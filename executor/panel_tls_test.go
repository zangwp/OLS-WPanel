package executor

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNormalizePanelDomain(t *testing.T) {
	for _, bad := range []string{"", "192.0.2.1", "https://panel.example.com", "panel.example.com:8443", "panel.example.com/path", "-panel.example.com", "panel.example.com\nother"} {
		if _, err := NormalizePanelDomain(bad); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
	if got, err := NormalizePanelDomain(" Panel.Example.COM "); err != nil || got != "panel.example.com" {
		t.Fatalf("normalization: %q %v", got, err)
	}
}
func TestPanelTLSRejectsTraversalGeneration(t *testing.T) {
	root := t.TempDir()
	cert := filepath.Join(root, "panel.crt")
	if err := os.WriteFile(filepath.Join(root, "panel-tls-active.json"), []byte(`{"domain":"panel.example.com","generation":"../outside"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadPanelTLSState(cert); err == nil {
		t.Fatal("accepted traversal")
	}
}
