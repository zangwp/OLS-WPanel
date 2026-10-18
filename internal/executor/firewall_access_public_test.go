package executor

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestAccessPreviewDescribesNewPublicSensitiveRules(t *testing.T) {
	management := []FirewallAccessRule{{Protocol: "tcp", Port: 22}, {Protocol: "tcp", Port: 8443}}
	public := FirewallAccessRule{Protocol: "tcp", Port: 7080}
	for _, tc := range []struct {
		name     string
		previous []FirewallAccessRule
		edit     func(string) string
		next     []FirewallAccessRule
		want     []FirewallAccessRule
	}{
		{name: "first apply", next: []FirewallAccessRule{public}, want: []FirewallAccessRule{public}},
		{name: "restricted becomes public", previous: []FirewallAccessRule{{Protocol: "tcp", Port: 7080, Source: "203.0.113.0/24"}}, next: []FirewallAccessRule{public}, want: []FirewallAccessRule{public}},
		{name: "unchanged verified public", previous: []FirewallAccessRule{public}, next: []FirewallAccessRule{public}, want: []FirewallAccessRule{}},
		{name: "counter rendering does not change exposure", previous: []FirewallAccessRule{public}, edit: func(table string) string {
			return strings.ReplaceAll(table, "counter accept", "counter packets 3 bytes 180 accept")
		}, next: []FirewallAccessRule{public}, want: []FirewallAccessRule{}},
		{name: "forged public comment requires confirmation", previous: []FirewallAccessRule{public}, edit: func(table string) string {
			return strings.Replace(table, "tcp dport 7080", "ip saddr 203.0.113.0/24 tcp dport 7080", 1)
		}, next: []FirewallAccessRule{public}, want: []FirewallAccessRule{public}},
		{name: "unknown table content requires confirmation", previous: []FirewallAccessRule{public}, edit: func(table string) string {
			return strings.Replace(table, "iifname", "tcp dport 7080 drop\niifname", 1)
		}, next: []FirewallAccessRule{public}, want: []FirewallAccessRule{public}},
		{name: "new protocol is a separate exposure", previous: []FirewallAccessRule{public}, next: []FirewallAccessRule{public, {Protocol: "UDP", Port: 7080}}, want: []FirewallAccessRule{{Protocol: "udp", Port: 7080}}},
		{name: "closing public access", previous: []FirewallAccessRule{public}, next: []FirewallAccessRule{{Protocol: "tcp", Port: 7080, Source: "203.0.113.5"}}, want: []FirewallAccessRule{}},
		{name: "all sensitive ports normalized and deduplicated", next: []FirewallAccessRule{
			{Protocol: "TCP", Port: 7080}, {Protocol: "tcp", Port: 7080},
			{Protocol: "udp", Port: 6379}, {Protocol: "tcp", Port: 3306},
			{Protocol: "tcp", Port: 8080}, {Protocol: "udp", Port: 3306, Source: "203.0.113.5"},
		}, want: []FirewallAccessRule{{Protocol: "tcp", Port: 3306}, {Protocol: "udp", Port: 6379}, public}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			state := newAccessFingerprintFixture(t, tc.previous != nil)
			if tc.previous != nil {
				state.owned = accessRulesScript(append(append([]FirewallAccessRule{}, management...), tc.previous...), false)
			}
			if tc.edit != nil {
				state.owned = tc.edit(state.owned)
			}
			rules := append(append([]FirewallAccessRule{}, management...), tc.next...)
			preview, err := PreviewFirewallAccess(FirewallAccessRequest{Rules: rules}, "203.0.113.5")
			if err != nil || !reflect.DeepEqual(preview.PublicExposure, tc.want) {
				t.Fatalf("exposure = %+v, want %+v: %v", preview.PublicExposure, tc.want, err)
			}
			if state.writes != 0 || state.timers != 0 || state.saved {
				t.Fatal("preview changed firewall state")
			}
			body, err := json.Marshal(preview)
			if err != nil {
				t.Fatal(err)
			}
			var contract struct {
				Exposure []FirewallAccessRule `json:"public_exposure"`
			}
			if err := json.Unmarshal(body, &contract); err != nil || !reflect.DeepEqual(contract.Exposure, tc.want) {
				t.Fatalf("public exposure was lost through JSON: %s, %v", body, err)
			}
		})
	}
}

func TestAccessApplyRequiresExplicitPublicConfirmationBeforeMutation(t *testing.T) {
	for _, exists := range []bool{false, true} {
		for _, confirmed := range []bool{false, true} {
			name := "first apply"
			if exists {
				name = "existing managed policy"
			}
			if confirmed {
				name += "/confirmed"
			} else {
				name += "/unconfirmed"
			}
			t.Run(name, func(t *testing.T) {
				state := newAccessFingerprintFixture(t, exists)
				rules := []FirewallAccessRule{{Protocol: "tcp", Port: 22}, {Protocol: "tcp", Port: 8443}, {Protocol: "tcp", Port: 7080}}
				preview, request := accessPreviewRoundTrip(t, rules)
				if len(preview.PublicExposure) != 1 {
					t.Fatalf("missing public exposure: %+v", preview)
				}
				body, err := json.Marshal(map[string]any{"rules": request.Rules, "fingerprint": request.Fingerprint, "confirm_public": confirmed})
				if err != nil {
					t.Fatal(err)
				}
				if err := json.Unmarshal(body, &request); err != nil {
					t.Fatal(err)
				}
				result, err := ApplyFirewallAccess(request, "203.0.113.5")
				if !confirmed {
					if err == nil || !strings.Contains(err.Error(), "确认公网访问风险") || state.writes != 0 || state.timers != 0 || state.saved {
						t.Fatalf("unconfirmed exposure changed state: %+v, %+v, %v", result, state, err)
					}
					if _, err := os.Stat(firewallAccessChangePath); !errors.Is(err, os.ErrNotExist) {
						t.Fatalf("unconfirmed exposure created a rollback receipt: %v", err)
					}
					files, err := os.ReadDir(accessRunDirectory)
					if err != nil || len(files) != 0 {
						t.Fatalf("unconfirmed exposure staged rule files: %v, %v", files, err)
					}
					return
				}
				if err != nil || state.writes != 1 {
					t.Fatalf("explicitly confirmed exposure was not applied: %+v, %+v, %v", result, state, err)
				}
				if exists {
					if !result.Saved || !state.saved || state.timers != 0 || result.RequiresConfirmation {
						t.Fatalf("public confirmation changed management save behavior: %+v, %+v", result, state)
					}
				} else if result.Saved || state.saved || !result.RequiresConfirmation || state.timers != 1 || result.ConfirmationToken == "" {
					t.Fatalf("public confirmation bypassed initial management rollback: %+v, %+v", result, state)
				}
			})
		}
	}
}

func TestAccessExistingPublicRulesOnlySkipConfirmationWhenVerified(t *testing.T) {
	for _, drift := range []bool{false, true} {
		t.Run(map[bool]string{false: "unchanged public", true: "drifted policy"}[drift], func(t *testing.T) {
			state := newAccessFingerprintFixture(t, true)
			rules := []FirewallAccessRule{{Protocol: "tcp", Port: 22}, {Protocol: "tcp", Port: 8443}, {Protocol: "tcp", Port: 7080}}
			state.owned = accessRulesScript(rules, false)
			if drift {
				state.owned = strings.Replace(state.owned, "tcp dport 7080", "tcp dport 7081", 1)
			}
			_, request := accessPreviewRoundTrip(t, rules)
			result, err := ApplyFirewallAccess(request, "203.0.113.5")
			if drift {
				if err == nil || state.writes != 0 || state.timers != 0 || state.saved {
					t.Fatalf("forged public comment bypassed confirmation: %+v, %v", result, err)
				}
			} else if err != nil || !result.Saved || !state.saved || state.writes != 1 {
				t.Fatalf("unchanged verified public access asked again: %+v, %v", result, err)
			}
		})
	}
}

func TestAccessPublicConfirmationCannotBypassChangedPreview(t *testing.T) {
	state := newAccessFingerprintFixture(t, true)
	rules := []FirewallAccessRule{{Protocol: "tcp", Port: 22}, {Protocol: "tcp", Port: 8443}, {Protocol: "tcp", Port: 7080, Source: "203.0.113.5"}}
	_, request := accessPreviewRoundTrip(t, rules)
	request.Rules[2].Source = ""
	request.ConfirmPublic = true
	if _, err := ApplyFirewallAccess(request, "203.0.113.5"); !errors.Is(err, ErrFirewallAccessPreviewChanged) || state.writes != 0 || state.timers != 0 || state.saved {
		t.Fatalf("public confirmation bypassed changed fingerprint: %+v, %v", state, err)
	}
}

func TestAccessPublicSaveRejectsPolicyChangeAfterPreviewRecheck(t *testing.T) {
	state := newAccessFingerprintFixture(t, true)
	rules := []FirewallAccessRule{{Protocol: "tcp", Port: 22}, {Protocol: "tcp", Port: 8443}, {Protocol: "tcp", Port: 7080}}
	state.owned = accessRulesScript(rules, false)
	_, request := accessPreviewRoundTrip(t, rules)
	fixtureCommand := portCommand
	reads := 0
	portCommand = func(ctx context.Context, name string, args ...string) (string, error) {
		if name == "nft" && strings.Join(args, " ") == "--stateless list table inet "+accessTable {
			reads++
			if reads == 2 {
				state.owned = accessRulesScript(rules[:2], false)
			}
		}
		return fixtureCommand(ctx, name, args...)
	}
	if _, err := ApplyFirewallAccess(request, "203.0.113.5"); err == nil || !strings.Contains(err.Error(), "访问策略已变化") || state.writes != 0 || state.timers != 0 || state.saved {
		t.Fatalf("new exposure after the last preview read bypassed confirmation: %+v, %v", state, err)
	}
}
