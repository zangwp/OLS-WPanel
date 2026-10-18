package executor

import (
	"errors"
	"os/user"
	"strings"
	"testing"
)

func stubOLSVHostExecutionAccounts(t *testing.T, uid, primaryGID, groupGID string) {
	t.Helper()
	oldUser, oldGroup := lookupOLSVHostExecutionUser, lookupOLSVHostExecutionGroup
	lookupOLSVHostExecutionUser = func(name string) (*user.User, error) {
		return &user.User{Username: name, Uid: uid, Gid: primaryGID}, nil
	}
	lookupOLSVHostExecutionGroup = func(name string) (*user.Group, error) {
		return &user.Group{Name: name, Gid: groupGID}, nil
	}
	t.Cleanup(func() {
		lookupOLSVHostExecutionUser, lookupOLSVHostExecutionGroup = oldUser, oldGroup
	})
}

const olsIdentityPHPFixture = "extprocessor lsphp_example {\n  extUser wp_example\n  extGroup wp_example\n}\n"

func TestReadOLSVHostExecutionIdentityKeepsExplicitSiteUser(t *testing.T) {
	stubOLSVHostExecutionAccounts(t, "998", "997", "997")
	for _, prefix := range []string{"", olsMetadataUserPrefix + "wp_example\n", "extraHeaders <<<END_headers\nextUser root\nextGroup root\n" + olsMetadataUserPrefix + "root\nEND_headers\n"} {
		got, err := readOLSVHostExecutionIdentity(prefix + olsIdentityPHPFixture)
		if err != nil || got != (olsVHostExecutionIdentity{user: "wp_example", group: "wp_example", scripts: true}) {
			t.Fatalf("identity = %+v, %v", got, err)
		}
	}
}

func TestReadOLSVHostExecutionIdentityRejectsAmbiguousOrMissingUsers(t *testing.T) {
	stubOLSVHostExecutionAccounts(t, "998", "997", "997")
	for name, content := range map[string]string{
		"missing":             "docRoot /www/example\n",
		"metadata only":       olsMetadataUserPrefix + "wp_example\ndocRoot /www/example\n",
		"missing group":       "extUser wp_example\n",
		"different group":     "extUser wp_example\nextGroup php_example\n",
		"different metadata":  olsMetadataUserPrefix + "wp_other\n" + olsIdentityPHPFixture,
		"empty metadata":      strings.TrimSpace(olsMetadataUserPrefix) + "\n" + olsIdentityPHPFixture,
		"duplicate metadata":  strings.Repeat(olsMetadataUserPrefix+"wp_example\n", 2) + olsIdentityPHPFixture,
		"duplicate user":      olsIdentityPHPFixture + "extUser wp_example\n",
		"duplicate group":     olsIdentityPHPFixture + "extGroup wp_example\n",
		"extra processor":     olsIdentityPHPFixture + "extprocessor another {\n}\n",
		"root":                "extUser root\nextGroup root\n",
		"numeric user":        "extUser 0\nextGroup 0\n",
		"directive injection": "extUser wp_example user root\nextGroup wp_example\n",
	} {
		t.Run(name, func(t *testing.T) {
			if got, err := readOLSVHostExecutionIdentity(content); err == nil {
				t.Fatalf("unsafe identity accepted: %+v", got)
			}
		})
	}
}

func TestReadOLSVHostExecutionIdentityChecksNumericAccounts(t *testing.T) {
	for _, tc := range []struct{ name, uid, primaryGID, groupGID string }{
		{"root alias", "0", "997", "997"},
		{"low user", "10", "997", "997"},
		{"low group", "998", "9", "9"},
		{"wrong primary group", "998", "996", "997"},
		{"invalid uid", "invalid", "997", "997"},
		{"invalid gid", "998", "997", "invalid"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stubOLSVHostExecutionAccounts(t, tc.uid, tc.primaryGID, tc.groupGID)
			if _, err := readOLSVHostExecutionIdentity(olsIdentityPHPFixture); err == nil {
				t.Fatal("unsafe numeric identity accepted")
			}
		})
	}
	t.Run("minimum safe ids", func(t *testing.T) {
		stubOLSVHostExecutionAccounts(t, "11", "10", "10")
		if _, err := readOLSVHostExecutionIdentity(olsIdentityPHPFixture); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("lookup failure", func(t *testing.T) {
		stubOLSVHostExecutionAccounts(t, "998", "997", "997")
		lookupOLSVHostExecutionUser = func(string) (*user.User, error) { return nil, errors.New("missing") }
		if _, err := readOLSVHostExecutionIdentity(olsIdentityPHPFixture); err == nil {
			t.Fatal("missing user accepted")
		}
		lookupOLSVHostExecutionUser = func(name string) (*user.User, error) {
			return &user.User{Username: name, Uid: "998", Gid: "997"}, nil
		}
		lookupOLSVHostExecutionGroup = func(string) (*user.Group, error) { return nil, errors.New("missing") }
		if _, err := readOLSVHostExecutionIdentity(olsIdentityPHPFixture); err == nil {
			t.Fatal("missing group accepted")
		}
	})
}

const olsIdentityMaintenanceFixture = `# OLS-WPanel-Format: 1
# OLS-WPanel-VHost: olsw_example
# OLS-WPanel-Domains: example.com
# OLS-WPanel-VHRoot: /www/maintenance
docRoot /www/maintenance
vhDomain example.com
enableGzip 0
index {
 useServer 0
 indexFiles maintenance.html
}
context / {
 type NULL
 location /www/maintenance/
 allowBrowse 1
 extraHeaders <<<END_headers
Cache-Control: no-store
X-OLS-WPanel-Backup: 31a48bf0-32c7-4a19-9237-27d4738fbdd9
END_headers
}
rewrite {
 enable 1
 autoLoadHtaccess 0
 rules <<<END_rules
RewriteRule ^ - [R=503,L]
END_rules
}
`

func TestReadOLSVHostExecutionIdentityKeepsBackupMaintenanceStatic(t *testing.T) {
	stubOLSVHostExecutionAccounts(t, "33", "33", "33")
	for _, ssl := range []string{"", "vhssl {\n keyFile /cert/key.pem\n certFile /cert/fullchain.pem\n certChain 1\n sslProtocol 24\n}\n"} {
		for _, metadataUser := range []string{"", "wp_example"} {
			content, wantUser := olsIdentityMaintenanceFixture+ssl, "www-data"
			if metadataUser != "" {
				content, wantUser = olsMetadataUserPrefix+metadataUser+"\n"+content, metadataUser
			}
			got, err := readOLSVHostExecutionIdentity(content)
			if err != nil || got != (olsVHostExecutionIdentity{user: wantUser, group: wantUser}) {
				t.Fatalf("static identity = %+v, %v", got, err)
			}
		}
	}
}

func TestReadOLSVHostExecutionIdentityRejectsMaintenanceWithExecutableChanges(t *testing.T) {
	stubOLSVHostExecutionAccounts(t, "33", "33", "33")
	for name, content := range map[string]string{
		"include":          olsIdentityMaintenanceFixture + "include /other.conf\n",
		"script handler":   olsIdentityMaintenanceFixture + "scripthandler {\n add lsapi:serverphp php\n}\n",
		"proxy":            strings.Replace(olsIdentityMaintenanceFixture, "type NULL", "type proxy", 1),
		"htaccess":         strings.Replace(olsIdentityMaintenanceFixture, "autoLoadHtaccess 0", "autoLoadHtaccess 1", 1),
		"different root":   strings.Replace(olsIdentityMaintenanceFixture, "location /www/maintenance/", "location /www/live/", 1),
		"invalid marker":   strings.Replace(olsIdentityMaintenanceFixture, "31a48bf0-32c7-4a19-9237-27d4738fbdd9", "invalid", 1),
		"no deny rule":     strings.Replace(olsIdentityMaintenanceFixture, "RewriteRule ^ - [R=503,L]", "RewriteRule ^ - [L]", 1),
		"unsafe index":     strings.Replace(olsIdentityMaintenanceFixture, "indexFiles maintenance.html", "indexFiles index.php", 1),
		"invalid hostname": strings.Replace(olsIdentityMaintenanceFixture, "vhDomain example.com", "vhDomain invalid;host", 1),
	} {
		t.Run(name, func(t *testing.T) {
			if got, err := readOLSVHostExecutionIdentity(content); err == nil {
				t.Fatalf("unsafe maintenance accepted: %+v", got)
			}
		})
	}
}
