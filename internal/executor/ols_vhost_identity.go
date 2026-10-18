package executor

import (
	"fmt"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

const olsMetadataUserPrefix = "# OLS-WPanel-SystemUser: "

type olsVHostExecutionIdentity struct {
	user, group string
	scripts     bool
}

var (
	lookupOLSVHostExecutionUser       = user.Lookup
	lookupOLSVHostExecutionGroup      = user.LookupGroup
	olsLegacyStaticMaintenancePattern = regexp.MustCompile(`(?s)^docRoot ([^\s{}]+)\nvhDomain ([^\s{}]+)\n(?:vhAliases ([^\n]+)\n)?enableGzip 0\nindex \{\nuseServer 0\nindexFiles maintenance\.html\n\}\ncontext / \{\ntype NULL\nlocation ([^\s{}]+)\nallowBrowse 1\nextraHeaders <<<END_headers\nCache-Control: no-store\nX-OLS-WPanel-Backup: ([^\s{}]+)\nEND_headers\n\}\nrewrite \{\nenable 1\nautoLoadHtaccess 0\nrules <<<END_rules\nRewriteRule \^ - \[R=503,L\]\nEND_rules\n\}(?:\nvhssl \{\nkeyFile [^\s{}]+\ncertFile [^\s{}]+\ncertChain 1\nsslProtocol [0-9]+\n\})?$`)
	olsStaticMaintenancePattern       = regexp.MustCompile(`(?s)^docRoot ([^\s{}]+)\nvhDomain ([^\s{}]+)\n(?:vhAliases ([^\n]+)\n)?enableGzip 0\nindex \{\nuseServer 0\nindexFiles maintenance\.html\n\}\ncontext / \{\ntype NULL\nlocation ([^\s{}]+)\nallowBrowse 1\nextraHeaders <<<END_headers\nset Cache-Control "no-store"\nset X-OLS-WPanel-Backup "([^\s{}"]+)"\nEND_headers\nrewrite \{\nenable 1\ninherit 0\nrules <<<END_rules\nRewriteRule \^ - \[R=503,L\]\nEND_rules\n\}\n\}\nrewrite \{\nenable 1\nautoLoadHtaccess 0\n\}(?:\nvhssl \{\nkeyFile [^\s{}]+\ncertFile [^\s{}]+\ncertChain 1\nsslProtocol [0-9]+\n\})?$`)
)

func readOLSVHostExecutionIdentity(content string) (olsVHostExecutionIdentity, error) {
	var identity olsVHostExecutionIdentity
	var metadataUser, extUser, extGroup string
	var userCount, extUserCount, extGroupCount, processorCount int
	var heredoc string
	inProcessor := false
	var body []string
	for _, raw := range strings.Split(content, "\n") {
		line := strings.TrimSpace(raw)
		if heredoc != "" {
			body = append(body, strings.Join(strings.Fields(line), " "))
			if line == heredoc {
				heredoc = ""
			}
			continue
		}
		if strings.HasPrefix(line, strings.TrimSpace(olsMetadataUserPrefix)) {
			userCount++
			metadataUser = strings.TrimSpace(strings.TrimPrefix(line, strings.TrimSpace(olsMetadataUserPrefix)))
		}
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		body = append(body, strings.Join(fields, " "))
		if index := strings.Index(line, "<<<"); index >= 0 {
			heredoc = strings.TrimSpace(line[index+3:])
			continue
		}
		switch strings.ToLower(fields[0]) {
		case "extprocessor":
			processorCount++
			if inProcessor || len(fields) != 3 || fields[2] != "{" {
				return identity, fmt.Errorf("invalid OpenLiteSpeed external processor")
			}
			inProcessor = true
		case "}":
			inProcessor = false
		case "extuser", "extgroup":
			if !inProcessor || len(fields) != 2 {
				return identity, fmt.Errorf("invalid OpenLiteSpeed execution identity directive")
			}
			if strings.EqualFold(fields[0], "extUser") {
				extUserCount++
				extUser = fields[1]
			} else {
				extGroupCount++
				extGroup = fields[1]
			}
		}
	}
	if heredoc != "" || inProcessor || userCount > 1 || processorCount > 1 || extUserCount > 1 || extGroupCount > 1 {
		return identity, fmt.Errorf("ambiguous OpenLiteSpeed execution identity")
	}
	if processorCount != 0 || extUserCount != 0 || extGroupCount != 0 {
		if processorCount != 1 || extUserCount != 1 || extGroupCount != 1 || extUser != extGroup || (userCount == 1 && metadataUser != extUser) {
			return identity, fmt.Errorf("inconsistent OpenLiteSpeed execution identity")
		}
		identity = olsVHostExecutionIdentity{user: extUser, group: extGroup, scripts: true}
	} else if isOLSStaticBackupMaintenance(strings.Join(body, "\n"), userCount == 1) {
		identity = olsVHostExecutionIdentity{user: "www-data", group: "www-data"}
		if userCount == 1 {
			identity.user, identity.group = metadataUser, metadataUser
		}
	} else {
		return identity, fmt.Errorf("OpenLiteSpeed configuration has no managed execution identity")
	}
	if err := validateOLSVHostExecutionIdentity(identity); err != nil {
		return olsVHostExecutionIdentity{}, err
	}
	return identity, nil
}

func isOLSStaticBackupMaintenance(content string, hasMetadata bool) bool {
	match := olsLegacyStaticMaintenancePattern.FindStringSubmatch(content)
	if match == nil && hasMetadata {
		match = olsStaticMaintenancePattern.FindStringSubmatch(content)
	}
	if match == nil || !validSiteBackupID(match[5]) || filepath.Clean(match[1]) != filepath.Clean(match[4]) {
		return false
	}
	var aliases []string
	if match[3] != "" {
		aliases = strings.Split(match[3], ",")
	}
	_, err := normalizeOLSDomains(match[2], aliases)
	return err == nil
}

func validateOLSVHostExecutionIdentity(identity olsVHostExecutionIdentity) error {
	if !olsSafeUserPattern.MatchString(identity.user) || identity.user == "root" || identity.user != identity.group {
		return fmt.Errorf("invalid OpenLiteSpeed execution user/group")
	}
	account, err := lookupOLSVHostExecutionUser(identity.user)
	if err != nil || account == nil {
		return fmt.Errorf("OpenLiteSpeed execution user %q is unavailable", identity.user)
	}
	group, err := lookupOLSVHostExecutionGroup(identity.group)
	if err != nil || group == nil {
		return fmt.Errorf("OpenLiteSpeed execution group %q is unavailable", identity.group)
	}
	uid, uidErr := strconv.Atoi(account.Uid)
	primaryGID, primaryErr := strconv.Atoi(account.Gid)
	gid, gidErr := strconv.Atoi(group.Gid)
	if uidErr != nil || primaryErr != nil || gidErr != nil || uid < 11 || gid < 10 || gid != primaryGID {
		return fmt.Errorf("OpenLiteSpeed execution user/group must use matching unprivileged IDs")
	}
	return nil
}
