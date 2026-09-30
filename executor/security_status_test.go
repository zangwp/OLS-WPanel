package executor

import "testing"

func TestCountSecurityListEntries(t *testing.T) {
	if got := countSecurityListEntries("203.0.113.1\n\n  2001:db8::1  \n"); got != 2 {
		t.Fatalf("countSecurityListEntries() = %d, want 2", got)
	}
}
