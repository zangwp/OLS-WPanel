package executor

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func requireWordPressCronCurl(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("curl unavailable: local HTTP integration requires the production command")
	}
	// Never route the loopback fixture through a developer's outbound proxy.
	t.Setenv("NO_PROXY", "127.0.0.1,localhost")
	t.Setenv("no_proxy", "127.0.0.1,localhost")
}

func TestWordPressCronPersistsHTTPFailuresAndSuccess(t *testing.T) {
	requireWordPressCronCurl(t)
	for _, code := range []int{http.StatusOK, http.StatusNoContent, http.StatusForbidden, http.StatusInternalServerError} {
		for _, scheduled := range []bool{false, true} {
			t.Run(fmt.Sprintf("http_%d_scheduled_%t", code, scheduled), func(t *testing.T) {
				db := setupCronGateTest(t)
				var calls atomic.Int32
				server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					calls.Add(1)
					if r.Method != http.MethodGet || r.URL.RequestURI() != "/wp-cron.php?doing_wp_cron" {
						t.Errorf("unexpected WordPress cron request: %s %s", r.Method, r.URL.RequestURI())
					}
					w.WriteHeader(code)
				}))
				defer server.Close()
				if _, err := db.Exec(`INSERT INTO cron_jobs
					(id,name,cron_expression,command,task_type,enabled,running)
					VALUES(81,'HTTP fixture','* * * * *',?,'wp_cron',1,1)`, strings.TrimPrefix(server.URL, "https://")); err != nil {
					t.Fatal(err)
				}

				result := runCronJob(81, scheduled)
				wantSuccess := code < 400
				if result.Success != wantSuccess || calls.Load() != 1 {
					t.Fatalf("HTTP %d result=%+v, calls=%d", code, result, calls.Load())
				}
				var status, output string
				var running int
				if err := db.QueryRow(`SELECT last_status,last_output,running FROM cron_jobs WHERE id=81`).Scan(&status, &output, &running); err != nil {
					t.Fatal(err)
				}
				wantStatus := "success"
				wantExit := "exit:0"
				if !wantSuccess {
					wantStatus, wantExit = "failed", "exit:1"
					if !strings.Contains(output, fmt.Sprint(code)) {
						t.Fatalf("failure output does not identify HTTP %d: %q", code, output)
					}
				}
				data, ok := result.Data.(map[string]interface{})
				if !ok || data["status"] != wantStatus || data["output"] != output || status != wantStatus {
					t.Fatalf("returned/persisted result disagree: result=%+v, status=%q output=%q", result, status, output)
				}
				if !scheduled && running != 0 {
					t.Fatal("manual HTTP invocation left the running claim set")
				}
				log, err := os.ReadFile(cronLogFile)
				if err != nil || !strings.Contains(string(log), wantExit) {
					t.Fatalf("log does not reflect %s: %q, err=%v", wantExit, log, err)
				}
			})
		}
	}
}

func TestWordPressCronRequestCannotSucceedOnConnectionFailure(t *testing.T) {
	requireWordPressCronCurl(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := runWordPressCronRequest(ctx, "https://"+address+"/wp-cron.php?doing_wp_cron"); err == nil {
		t.Fatal("unreachable origin was treated as a successful WordPress cron invocation")
	}
}

func TestWordPressCronRequestHonorsCancellation(t *testing.T) {
	requireWordPressCronCurl(t)
	started := make(chan struct{})
	release := make(chan struct{})
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	defer server.Close()
	defer close(release)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := runWordPressCronRequest(ctx, server.URL+"/wp-cron.php?doing_wp_cron")
		done <- err
	}()
	select {
	case <-started:
	case err := <-done:
		t.Fatalf("request ended before reaching the local origin: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("local origin was not reached")
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("canceled WordPress cron request was treated as success")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("WordPress cron process did not exit after cancellation")
	}
}
