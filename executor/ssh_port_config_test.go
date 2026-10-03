package executor

import (
	"strings"
	"testing"
)

func TestSSHPortConfigPreservesAuthenticationAndMatch(t *testing.T) {
	original := "# administrator notes\nPort 22\nInclude /etc/ssh/sshd_config.d/*.conf\nPasswordAuthentication no\nMatch User deploy\n AllowTcpForwarding no\n"
	dual, e := sshPortConfig(original, 22, 2222)
	if e != nil {
		t.Fatal(e)
	}
	if strings.Count(dual, "Port 22\n") != 1 || !strings.Contains(dual, "Port 2222\n") {
		t.Fatal(dual)
	}
	for _, s := range []string{"# administrator notes", "Include /etc/ssh/sshd_config.d/*.conf", "PasswordAuthentication no", "Match User deploy\n AllowTcpForwarding no"} {
		if !strings.Contains(dual, s) {
			t.Fatalf("lost %s", s)
		}
	}
	final, e := sshPortConfig(dual, 2222)
	if e != nil {
		t.Fatal(e)
	}
	if strings.Contains(final, "Port 22\n") || strings.Count(final, "Port 2222\n") != 1 {
		t.Fatal(final)
	}
	if _, e = sshPortConfig(original, 65536); e == nil {
		t.Fatal("invalid port accepted")
	}
}

func TestSSHPortRejectsPinnedOrIncludedPorts(t *testing.T) {
	good := "port 22\nport 2222\nlistenaddress 0.0.0.0:22\nlistenaddress [::]:2222\n"
	if e := validateSSHPorts(good, 22, 2222); e != nil {
		t.Fatal(e)
	}
	for _, out := range []string{"port 2222\nport 22\nlistenaddress 0.0.0.0:2222\n", "port 22\nport 2222\nlistenaddress 0.0.0.0:22\n", "port 2222\nlistenaddress 0.0.0.0:22\n"} {
		if e := validateSSHPorts(out, 2222); e == nil {
			t.Fatalf("conflict accepted: %s", out)
		}
	}
	if e := validateSSHPorts("port 22\nport 2222\nlistenaddress 0.0.0.0:22\n", 22, 2222); e == nil {
		t.Fatal("pinned address failed to create new listener")
	}
}

func TestSSHAccessMigrationPreservesSourcesAndOtherServices(t *testing.T) {
	original := []FirewallAccessRule{{"tcp", 22, "203.0.113.0/24"}, {"tcp", 22, "2001:db8::/64"}, {"tcp", 443, ""}, {"udp", 443, ""}}
	dual, e := migrateSSHAccess(original, 22, 2222, true)
	if e != nil || len(dual) != 6 {
		t.Fatalf("%+v %v", dual, e)
	}
	final, e := migrateSSHAccess(original, 22, 2222, false)
	if e != nil || len(final) != 4 {
		t.Fatalf("%+v %v", final, e)
	}
	if final[0].Source != original[0].Source || final[1].Source != original[1].Source || final[2] != original[2] || final[3] != original[3] {
		t.Fatal("source or unrelated service changed")
	}
	for _, r := range final {
		if r.Port == 22 {
			t.Fatal("old SSH port remains")
		}
	}
	if _, e = migrateSSHAccess(append(original, FirewallAccessRule{"tcp", 2222, ""}), 22, 2222, true); e == nil {
		t.Fatal("existing destination policy overwritten")
	}
	if _, e = migrateSSHAccess(original, 2200, 2222, true); e == nil {
		t.Fatal("missing old SSH policy accepted")
	}
}
