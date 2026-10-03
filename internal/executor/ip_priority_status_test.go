package executor

import "testing"

func TestIPPriorityOwnershipStatus(t *testing.T) {
	for _, tc := range []struct {
		name, content, source, mode string
		change, restore             bool
	}{
		{"default", "# precedence ::/0 40\n", "default", "default", true, false},
		{"external", "precedence ::ffff:0:0/96 100\n", "external", "custom", false, false},
		{"managed", ipPriorityBegin + "\nprecedence ::ffff:0:0/96 100\n" + ipPriorityEnd + "\n", "managed", "ipv4", true, true},
		{"mixed", "precedence ::/0 40\n" + ipPriorityBegin + "\nprecedence ::ffff:0:0/96 100\n" + ipPriorityEnd + "\n", "external", "custom", false, true},
		{"broken", ipPriorityBegin + "\nprecedence ::/0 100\n", "invalid", "default", false, false},
		{"duplicate", ipPriorityBegin + "\nprecedence ::/0 100\n" + ipPriorityEnd + "\n" + ipPriorityBegin + "\nprecedence ::/0 50\n" + ipPriorityEnd + "\n", "invalid", "default", false, false},
		{"nested", ipPriorityBegin + "\n" + ipPriorityBegin + "\nprecedence ::/0 100\n" + ipPriorityEnd + "\n", "invalid", "default", false, false},
		{"marker suffix", ipPriorityBegin + "\nprecedence ::/0 100\n" + ipPriorityEnd + "-administrator-rule\n", "invalid", "default", false, false},
		{"windows line endings", ipPriorityBegin + "\r\nprecedence ::ffff:0:0/96 100\r\n" + ipPriorityEnd + "\r\n", "managed", "ipv4", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := parseIPPriorityStatus(tc.content)
			if got.Source != tc.source || got.Mode != tc.mode || got.CanChange != tc.change || got.CanRestore != tc.restore {
				t.Fatalf("unexpected status: %+v", got)
			}
		})
	}
}
