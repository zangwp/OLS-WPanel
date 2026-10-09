package executor

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

type wpAccessRouteTransport func(*http.Request) (*http.Response, error)

func (f wpAccessRouteTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestWPPanelAccessLoginRouteRefusesRedirectsMissingProofAndCancellation(t *testing.T) {
	generation := strings.Repeat("b", 32)
	for _, test := range []struct {
		status int
		marker string
		valid  bool
	}{{200, generation, true}, {200, "", false}, {200, strings.Repeat("c", 32), false}, {404, generation, false}, {302, generation, false}} {
		calls := 0
		client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }, Transport: wpAccessRouteTransport(func(r *http.Request) (*http.Response, error) {
			calls++
			if r.Method != "GET" || r.URL.String() != "https://example.com/wp/staff-signin" {
				t.Fatal("route proof submitted credentials or changed its target")
			}
			return &http.Response{StatusCode: test.status, Header: http.Header{"X-Ols-Wpanel-Login-Route": []string{test.marker}, "Location": []string{"https://evil.test/"}}, Body: io.NopCloser(strings.NewReader("login page")), Request: r}, nil
		})}
		err := verifyWPPanelAccessLoginRouteWithClient(context.Background(), client, "https://example.com/wp/staff-signin", generation)
		if (err == nil) != test.valid || calls != 1 {
			t.Fatalf("route status=%d marker=%q valid=%t requests=%d", test.status, test.marker, err == nil, calls)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	client := &http.Client{Transport: wpAccessRouteTransport(func(r *http.Request) (*http.Response, error) {
		if !errors.Is(r.Context().Err(), context.Canceled) {
			t.Fatal("probe lost request cancellation")
		}
		return nil, r.Context().Err()
	})}
	if err := verifyWPPanelAccessLoginRouteWithClient(ctx, client, "https://example.com/wp/staff-signin", generation); err == nil {
		t.Fatal("cancelled route proof succeeded")
	}
}
