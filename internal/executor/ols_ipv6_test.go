package executor

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func olsIPv6NetworkFixture() ([]olsIPv6Interface, []olsIPv6Route) {
	return []olsIPv6Interface{{Name: "eth0", Flags: []string{"UP", "LOWER_UP"}, Addresses: []olsIPv6Address{{Family: "inet6", Local: "2001:4860:1234::2", Scope: "global"}}}}, []olsIPv6Route{{Destination: "default", Device: "eth0"}}
}

func TestOLSIPv6NetworkRequiresPublicReadyAddressAndMatchingDefaultRoute(t *testing.T) {
	cases := []struct {
		name string
		edit func([]olsIPv6Interface, []olsIPv6Route)
		want bool
	}{
		{"public network", func(a []olsIPv6Interface, r []olsIPv6Route) {}, true},
		{"temporary address", func(a []olsIPv6Interface, r []olsIPv6Route) { a[0].Addresses[0].Flags = []string{"temporary"} }, true},
		{"unicast onlink route", func(a []olsIPv6Interface, r []olsIPv6Route) { r[0].Type = "unicast"; r[0].Flags = []string{"onlink"} }, true},
		{"zero prefix route", func(a []olsIPv6Interface, r []olsIPv6Route) { r[0].Destination = "::/0" }, true},
		{"missing address", func(a []olsIPv6Interface, r []olsIPv6Route) { a[0].Addresses = nil }, false},
		{"interface down", func(a []olsIPv6Interface, r []olsIPv6Route) { a[0].Flags = []string{"BROADCAST"} }, false},
		{"loopback interface", func(a []olsIPv6Interface, r []olsIPv6Route) { a[0].Flags = []string{"UP", "LOOPBACK"} }, false},
		{"missing interface name", func(a []olsIPv6Interface, r []olsIPv6Route) { a[0].Name = "" }, false},
		{"ULA", func(a []olsIPv6Interface, r []olsIPv6Route) { a[0].Addresses[0].Local = "fd00::2" }, false},
		{"link local", func(a []olsIPv6Interface, r []olsIPv6Route) { a[0].Addresses[0].Local = "fe80::2" }, false},
		{"documentation address", func(a []olsIPv6Interface, r []olsIPv6Route) { a[0].Addresses[0].Local = "2001:db8::2" }, false},
		{"unspecified", func(a []olsIPv6Interface, r []olsIPv6Route) { a[0].Addresses[0].Local = "::" }, false},
		{"IPv4 mapped", func(a []olsIPv6Interface, r []olsIPv6Route) { a[0].Addresses[0].Local = "::ffff:203.0.113.2" }, false},
		{"invalid address", func(a []olsIPv6Interface, r []olsIPv6Route) { a[0].Addresses[0].Local = "invalid" }, false},
		{"wrong family", func(a []olsIPv6Interface, r []olsIPv6Route) { a[0].Addresses[0].Family = "inet" }, false},
		{"wrong scope", func(a []olsIPv6Interface, r []olsIPv6Route) { a[0].Addresses[0].Scope = "host" }, false},
		{"tentative boolean", func(a []olsIPv6Interface, r []olsIPv6Route) { a[0].Addresses[0].Tentative = true }, false},
		{"DAD failed boolean", func(a []olsIPv6Interface, r []olsIPv6Route) { a[0].Addresses[0].DADFailed = true }, false},
		{"deprecated boolean", func(a []olsIPv6Interface, r []olsIPv6Route) { a[0].Addresses[0].Deprecated = true }, false},
		{"tentative flag", func(a []olsIPv6Interface, r []olsIPv6Route) { a[0].Addresses[0].Flags = []string{"tentative"} }, false},
		{"DAD failed flag", func(a []olsIPv6Interface, r []olsIPv6Route) { a[0].Addresses[0].Flags = []string{"dadfailed"} }, false},
		{"deprecated flag", func(a []olsIPv6Interface, r []olsIPv6Route) { a[0].Addresses[0].Flags = []string{"deprecated"} }, false},
		{"expired preferred lifetime", func(a []olsIPv6Interface, r []olsIPv6Route) {
			a[0].Addresses[0].PreferredLifeTime = json.RawMessage(`0`)
		}, false},
		{"expired valid lifetime", func(a []olsIPv6Interface, r []olsIPv6Route) { a[0].Addresses[0].ValidLifeTime = json.RawMessage(`0`) }, false},
		{"different route interface", func(a []olsIPv6Interface, r []olsIPv6Route) { r[0].Device = "eth1" }, false},
		{"missing route interface", func(a []olsIPv6Interface, r []olsIPv6Route) { r[0].Device = "" }, false},
		{"nondefault route", func(a []olsIPv6Interface, r []olsIPv6Route) { r[0].Destination = "2001:4860::/32" }, false},
		{"unreachable route", func(a []olsIPv6Interface, r []olsIPv6Route) { r[0].Type = "unreachable" }, false},
		{"blackhole route", func(a []olsIPv6Interface, r []olsIPv6Route) { r[0].Type = "blackhole" }, false},
		{"dead route", func(a []olsIPv6Interface, r []olsIPv6Route) { r[0].Flags = []string{"dead"} }, false},
		{"linkdown route", func(a []olsIPv6Interface, r []olsIPv6Route) { r[0].Flags = []string{"linkdown"} }, false},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			addresses, routes := olsIPv6NetworkFixture()
			test.edit(addresses, routes)
			addressJSON, _ := json.Marshal(addresses)
			routeJSON, _ := json.Marshal(routes)
			if got := olsIPv6NetworkReady(addressJSON, routeJSON); got != test.want {
				t.Fatalf("network readiness = %v, want %v", got, test.want)
			}
		})
	}
	for _, data := range [][2]string{{`invalid`, `[]`}, {`[]`, `invalid`}, {`{}`, `[]`}, {`null`, `null`}, {`[]`, `[]`}} {
		if olsIPv6NetworkReady([]byte(data[0]), []byte(data[1])) {
			t.Fatalf("unreadable or empty network was accepted: %v", data)
		}
	}
}

type olsIPv6ProbeListener struct {
	closed bool
}

func (listener *olsIPv6ProbeListener) Accept() (net.Conn, error) { return nil, errors.New("unused") }
func (listener *olsIPv6ProbeListener) Addr() net.Addr            { return &net.TCPAddr{} }
func (listener *olsIPv6ProbeListener) Close() error              { listener.closed = true; return nil }

func TestProbeOLSIPv6FailsClosedWithoutRemoteConnections(t *testing.T) {
	oldCommand, oldListen := olsIPv6Command, olsIPv6Listen
	t.Cleanup(func() { olsIPv6Command, olsIPv6Listen = oldCommand, oldListen })
	for _, failure := range []string{"", "address", "route", "malformed", "kernel"} {
		t.Run(failure, func(t *testing.T) {
			addresses, routes := olsIPv6NetworkFixture()
			addressJSON, _ := json.Marshal(addresses)
			routeJSON, _ := json.Marshal(routes)
			calls, binds := []string{}, 0
			listener := &olsIPv6ProbeListener{}
			olsIPv6Command = func(ctx context.Context, name string, args ...string) ([]byte, error) {
				if name != "ip" {
					t.Fatalf("unexpected command %q", name)
				}
				if _, ok := ctx.Deadline(); !ok {
					t.Fatal("network detection must have a bounded context")
				}
				command := strings.Join(args, " ")
				calls = append(calls, command)
				switch command {
				case "-6 -j addr show up scope global":
					if failure == "address" {
						return nil, errors.New("ip unavailable")
					}
					if failure == "malformed" {
						return []byte(`invalid`), nil
					}
					return addressJSON, nil
				case "-6 -j route show default":
					if failure == "route" {
						return nil, errors.New("route unavailable")
					}
					return routeJSON, nil
				default:
					t.Fatalf("unexpected command arguments %q", command)
					return nil, nil
				}
			}
			olsIPv6Listen = func(network, address string) (net.Listener, error) {
				binds++
				if network != "tcp6" || address != "[::]:0" {
					t.Fatalf("unexpected bind %s %s", network, address)
				}
				if failure == "kernel" {
					return nil, errors.New("IPv6 disabled")
				}
				return listener, nil
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			if got := probeOLSIPv6(ctx); got != (failure == "") {
				t.Fatalf("probe = %v for failure %q", got, failure)
			}
			if failure == "" && (!listener.closed || binds != 1 || len(calls) != 2) {
				t.Fatalf("probe leaked its bind: closed=%v binds=%d calls=%v", listener.closed, binds, calls)
			}
			if failure != "" && failure != "kernel" && binds != 0 {
				t.Fatal("failed network detection must not bind a socket")
			}
		})
	}
}

func TestDetectOLSIPv6UnsupportedRuntimeKeepsIPv4(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("non-Linux guard")
	}
	oldCommand := olsIPv6Command
	t.Cleanup(func() { olsIPv6Command = oldCommand })
	olsIPv6Command = func(context.Context, string, ...string) ([]byte, error) {
		t.Fatal("unsupported runtime invoked ip")
		return nil, nil
	}
	if detectOLSIPv6() {
		t.Fatal("unsupported runtime enabled IPv6")
	}
}

func TestOLSWildcardWebListenersRequireBothPortsAndCorrectFamily(t *testing.T) {
	stubOLSListenerOwnership(t)
	for _, test := range []struct {
		name   string
		output string
		ipv6   bool
		want   bool
	}{
		{"IPv4 wildcard", "LISTEN 0 511 0.0.0.0:80 0.0.0.0:*\nLISTEN 0 511 0.0.0.0:443 0.0.0.0:*", false, true},
		{"IPv6 wildcard", "LISTEN 0 511 [::]:80 [::]:*\nLISTEN 0 511 [::]:443 [::]:*", true, true},
		{"IPv6 wildcard without brackets", "LISTEN 0 511 :::80 :::*\nLISTEN 0 511 :::443 :::*", true, true},
		{"unbracketed IPv6 cannot satisfy IPv4", "LISTEN 0 511 :::80 :::*\nLISTEN 0 511 :::443 :::*", false, false},
		{"family-specific star", "LISTEN 0 511 *:80 *:*\nLISTEN 0 511 *:443 *:*", true, true},
		{"IPv4 cannot satisfy IPv6", "LISTEN 0 511 0.0.0.0:80 *:*\nLISTEN 0 511 0.0.0.0:443 *:*", true, false},
		{"IPv6 cannot satisfy IPv4", "LISTEN 0 511 [::]:80 *:*\nLISTEN 0 511 [::]:443 *:*", false, false},
		{"IPv4 localhost", "LISTEN 0 511 127.0.0.1:80 *:*\nLISTEN 0 511 127.0.0.1:443 *:*", false, false},
		{"IPv6 localhost", "LISTEN 0 511 [::1]:80 *:*\nLISTEN 0 511 [::1]:443 *:*", true, false},
		{"public IPv6 is not wildcard", "LISTEN 0 511 [2001:4860::2]:80 *:*\nLISTEN 0 511 [2001:4860::2]:443 *:*", true, false},
		{"mapped IPv4 is not IPv6 wildcard", "LISTEN 0 511 [::ffff:0.0.0.0]:80 *:*\nLISTEN 0 511 [::ffff:0.0.0.0]:443 *:*", true, false},
		{"HTTPS missing", "LISTEN 0 511 [::]:80 *:*", true, false},
		{"HTTP missing", "LISTEN 0 511 [::]:443 *:*", true, false},
		{"other ports", "LISTEN 0 511 [::]:8080 *:*\nLISTEN 0 511 [::]:8443 *:*", true, false},
		{"not listening", "ESTAB 0 511 [::]:80 *:*\nESTAB 0 511 [::]:443 *:*", true, false},
		{"malformed", "LISTEN [::]:80\nLISTEN 0 511 malformed *:*", true, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := olsWildcardWebListenersReady(olsTestOwnedListeners(test.output), test.ipv6); got != test.want {
				t.Fatalf("ready = %v, want %v", got, test.want)
			}
		})
	}
}

func TestVerifyOLSIPv6ListenersRetriesStartupButRejectsCommandFailure(t *testing.T) {
	stubOLSListenerOwnership(t)
	for _, state := range []string{"ready", "startup delay", "IPv4 query fails", "IPv6 query fails with partial output"} {
		t.Run(state, func(t *testing.T) {
			old := olsIPv6Command
			t.Cleanup(func() { olsIPv6Command = old })
			var calls int
			olsIPv6Command = func(ctx context.Context, name string, args ...string) ([]byte, error) {
				calls++
				if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > 2*time.Second || name != "ss" || len(args) != 6 || strings.Join(args[:5], " ") != "-H -l -t -n -p" {
					t.Fatalf("unexpected or unbounded local listener query: %s %v", name, args)
				}
				host := "0.0.0.0"
				if args[5] == "-6" {
					host = "[::]"
				}
				output := olsTestOwnedListeners("LISTEN 0 511 " + host + ":80 *:*\nLISTEN 0 511 " + host + ":443 *:*\n")
				if (state == "IPv4 query fails" && args[5] == "-4") || (state == "IPv6 query fails with partial output" && args[5] == "-6") {
					return output, errors.New("query failed")
				}
				if state == "startup delay" && calls == 1 {
					return nil, nil
				}
				return output, nil
			}
			err := verifyOLSIPv6Listeners()
			failed := strings.Contains(state, "fails")
			if (err != nil) != failed {
				t.Fatalf("verification error = %v for %s", err, state)
			}
			wantCalls := 2
			if state == "startup delay" {
				wantCalls = 4
			} else if state == "IPv4 query fails" {
				wantCalls = 1
			}
			if calls != wantCalls {
				t.Fatalf("local queries = %d, want %d", calls, wantCalls)
			}
		})
	}
}

func TestVerifyOLSIPv4FallbackChecksOnlyIPv4AndRejectsPartialFailure(t *testing.T) {
	stubOLSListenerOwnership(t)
	for _, state := range []string{"ready", "startup delay", "query fails", "partial output with failure"} {
		t.Run(state, func(t *testing.T) {
			old := olsIPv6Command
			t.Cleanup(func() { olsIPv6Command = old })
			var calls int
			olsIPv6Command = func(ctx context.Context, name string, args ...string) ([]byte, error) {
				calls++
				deadline, ok := ctx.Deadline()
				if !ok || time.Until(deadline) > 2*time.Second || name != "ss" || strings.Join(args, " ") != "-H -l -t -n -p -4" {
					t.Fatalf("IPv4 fallback queried an unexpected family or unbounded command: %s %v", name, args)
				}
				output := olsTestOwnedListeners("LISTEN 0 511 0.0.0.0:80 *:*\nLISTEN 0 511 0.0.0.0:443 *:*\n")
				switch state {
				case "query fails":
					return nil, errors.New("query failed")
				case "partial output with failure":
					return output, errors.New("query failed after output")
				case "startup delay":
					if calls == 1 {
						return nil, nil
					}
				}
				return output, nil
			}
			err := verifyOLSWebListeners(false)
			failed := state == "query fails" || state == "partial output with failure"
			if (err != nil) != failed {
				t.Fatalf("IPv4 verification error = %v for %s", err, state)
			}
			wantCalls := 1
			if state == "startup delay" {
				wantCalls = 2
			}
			if calls != wantCalls {
				t.Fatalf("IPv4 queries = %d, want %d", calls, wantCalls)
			}
		})
	}
}

func stubOLSListenerOwnership(t *testing.T) {
	t.Helper()
	old := olsListenerProcessIsOLS
	olsListenerProcessIsOLS = func(pid string) bool { return pid == "4242" }
	t.Cleanup(func() { olsListenerProcessIsOLS = old })
}

func olsTestOwnedListeners(output string) []byte {
	var lines []string
	for _, line := range strings.Split(output, "\n") {
		if line != "" {
			lines = append(lines, line+` users:(("test-only-owner",pid=4242,fd=7))`)
		}
	}
	return []byte(strings.Join(lines, "\n"))
}

func TestOLSListenerOwnershipDoesNotTrustProcessNamesOrMissingOwners(t *testing.T) {
	stubOLSListenerOwnership(t)
	for _, tc := range []struct {
		name, owner string
		want        bool
	}{
		{"same executable different comm", `users:(("nginx",pid=4242,fd=7))`, true},
		{"different executable OLS comm", `users:(("openlitespeed",pid=9898,fd=7))`, false},
		{"missing owner", ``, false},
		{"owner hidden", `users:()`, false},
		{"pid inside quoted name", `users:(("fake,pid=4242,fd=7",pid=9898,fd=8))`, false},
		{"multiple confirmed owners", `users:(("worker",pid=4242,fd=7),("master",pid=4242,fd=8))`, true},
		{"foreign additional owner", `users:(("worker",pid=4242,fd=7),("foreign",pid=9898,fd=8))`, false},
		{"malformed pid", `users:(("worker",pid=4242x,fd=7))`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			output := "LISTEN 0 511 [::]:80 *:* " + tc.owner + "\nLISTEN 0 511 [::]:443 *:* " + tc.owner
			if got := olsWildcardWebListenersReady([]byte(output), true); got != tc.want {
				t.Fatal("ownership result", got, "want", tc.want)
			}
		})
	}
}

func TestOLSProcessOwnershipUsesActualExecutableFileIdentity(t *testing.T) {
	root := t.TempDir()
	expectedPath, otherPath := filepath.Join(root, "actual-ols"), filepath.Join(root, "other-server")
	for _, path := range []string{expectedPath, otherPath} {
		if err := os.WriteFile(path, []byte("test-only-file-not-executed"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, state := range []string{"same file", "other executable", "owner permission denied", "binary unavailable", "invalid PID"} {
		t.Run(state, func(t *testing.T) {
			pid := "4242"
			if state == "invalid PID" {
				pid = "../4242"
			}
			stat := func(path string) (os.FileInfo, error) {
				switch path {
				case expectedPath:
					if state == "binary unavailable" {
						return nil, os.ErrNotExist
					}
					return os.Stat(expectedPath)
				case "/proc/4242/exe":
					if state == "owner permission denied" {
						return nil, os.ErrPermission
					}
					if state == "other executable" {
						return os.Stat(otherPath)
					}
					return os.Stat(expectedPath)
				default:
					t.Fatal("unexpected ownership lookup", path)
					return nil, os.ErrNotExist
				}
			}
			if got := olsProcessUsesBinary(pid, expectedPath, stat); got != (state == "same file") {
				t.Fatal("actual file ownership result", got, state)
			}
		})
	}
}
