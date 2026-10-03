package executor

import (
	"errors"
	"os"
	"regexp"
	"strings"
)

const ipPriorityBegin = "# OLS WPanel IP priority begin"
const ipPriorityEnd = "# OLS WPanel IP priority end"

var (
	ipPriorityBlockRE    = regexp.MustCompile(`(?ms)^` + regexp.QuoteMeta(ipPriorityBegin) + `\r?\n.*?^` + regexp.QuoteMeta(ipPriorityEnd) + `(?:\r?\n|$)`)
	ipPriorityExternalRE = regexp.MustCompile(`(?m)^\s*precedence\s+`)
)

// splitIPPriorityContent is shared by the reader and writer so malformed,
// nested, or duplicate ownership markers can never be silently overwritten.
func splitIPPriorityContent(content string) (external, managed string, err error) {
	blocks := ipPriorityBlockRE.FindAllString(content, -1)
	if len(blocks) > 1 || strings.Count(content, ipPriorityBegin) != len(blocks) || strings.Count(content, ipPriorityEnd) != len(blocks) {
		return "", "", errors.New("invalid managed priority block")
	}
	if len(blocks) == 1 {
		managed = blocks[0]
	}
	return ipPriorityBlockRE.ReplaceAllString(content, ""), managed, nil
}

type IPPriorityStatus struct {
	Source     string   `json:"source"`
	Mode       string   `json:"mode"`
	CanChange  bool     `json:"can_change"`
	CanRestore bool     `json:"can_restore"`
	Rules      []string `json:"rules"`
}

func GetIPPriorityStatus() IPPriorityStatus {
	data, err := os.ReadFile("/etc/gai.conf")
	if err != nil && !os.IsNotExist(err) {
		return IPPriorityStatus{Source: "unavailable"}
	}
	return parseIPPriorityStatus(string(data))
}

func parseIPPriorityStatus(content string) IPPriorityStatus {
	status := IPPriorityStatus{Source: "default", Mode: "default", CanChange: true, Rules: []string{}}
	external, managed, err := splitIPPriorityContent(content)
	if err != nil {
		status.Source = "invalid"
		status.CanChange = false
		return status
	}
	for _, line := range strings.Split(content, "\n") {
		fields := strings.Fields(line)
		if len(fields) > 0 && (fields[0] == "precedence" || fields[0] == "label") {
			status.Rules = append(status.Rules, strings.TrimSpace(line))
		}
	}
	if managed != "" {
		status.Source = "managed"
		status.Mode = "custom"
		status.CanRestore = true
		rules := []string{}
		for _, line := range strings.Split(managed, "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "precedence ") {
				rules = append(rules, strings.Join(strings.Fields(line), " "))
			}
		}
		if strings.Join(rules, "\n") == "precedence ::ffff:0:0/96 100" {
			status.Mode = "ipv4"
		}
		if strings.Join(rules, "\n") == "precedence ::ffff:0:0/96 10\nprecedence ::/0 100" {
			status.Mode = "ipv6"
		}
	}
	if ipPriorityExternalRE.MatchString(external) {
		status.Source = "external"
		status.Mode = "custom"
		status.CanChange = false
	}
	return status
}
