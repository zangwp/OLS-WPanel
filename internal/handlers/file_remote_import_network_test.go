package handlers

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

func TestRemoteImportDialPinsValidatedDNSAddresses(t *testing.T) {
	lookups := 0
	lookup := func(context.Context, string) ([]net.IPAddr, error) {
		lookups++
		if lookups > 1 {
			return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
		}
		return []net.IPAddr{{IP: net.ParseIP("8.8.8.8")}, {IP: net.ParseIP("2001:4860:4860::8888")}}, nil
	}
	var targets []string
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	conn, err := dialRemoteImportResolved(context.Background(), "tcp", "changing.example:443", "en-US", lookup,
		func(ctx context.Context, network, address string) (net.Conn, error) {
			targets = append(targets, address)
			if address == "8.8.8.8:443" {
				return nil, errors.New("first address unavailable")
			}
			if address != "[2001:4860:4860::8888]:443" {
				t.Fatalf("unvalidated connection target: %q", address)
			}
			return left, nil
		})
	if err != nil || conn != left || lookups != 1 || len(targets) != 2 {
		t.Fatalf("conn=%v err=%v lookups=%d targets=%v", conn, err, lookups, targets)
	}
}

func TestRemoteImportDialRejectsAllMixedAndLiteralPrivateTargets(t *testing.T) {
	for _, host := range []string{"mixed.example", "127.0.0.1", "[::1]", "localhost", "metadata.localhost"} {
		t.Run(host, func(t *testing.T) {
			_, err := dialRemoteImportResolved(context.Background(), "tcp", host+":443", "en-US",
				func(context.Context, string) ([]net.IPAddr, error) {
					return []net.IPAddr{{IP: net.ParseIP("8.8.8.8")}, {IP: net.ParseIP("169.254.169.254")}}, nil
				}, func(context.Context, string, string) (net.Conn, error) {
					t.Fatal("unsafe target reached dial")
					return nil, nil
				})
			if err == nil {
				t.Fatal("expected rejection")
			}
		})
	}
}

func TestRemoteImportDialCancellationStopsFallback(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls := 0
	_, err := dialRemoteImportResolved(ctx, "tcp", "public.example:443", "en-US",
		func(context.Context, string) ([]net.IPAddr, error) {
			return []net.IPAddr{{IP: net.ParseIP("8.8.8.8")}, {IP: net.ParseIP("8.8.4.4")}}, nil
		}, func(context.Context, string, string) (net.Conn, error) {
			calls++
			cancel()
			return nil, context.Canceled
		})
	if !errors.Is(err, context.Canceled) || calls != 1 {
		t.Fatalf("err=%v calls=%d", err, calls)
	}
}

func TestRemoteImportDialReservesBudgetForHealthyFallback(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	calls := 0
	conn, err := dialRemoteImportResolved(ctx, "tcp", "public.example:443", "en-US",
		func(context.Context, string) ([]net.IPAddr, error) {
			return []net.IPAddr{{IP: net.ParseIP("2001:4860:4860::8888")}, {IP: net.ParseIP("8.8.8.8")}}, nil
		}, func(attempt context.Context, network, address string) (net.Conn, error) {
			calls++
			if calls == 1 {
				<-attempt.Done()
				return nil, attempt.Err()
			}
			return left, nil
		})
	if err != nil || conn != left || calls != 2 {
		t.Fatalf("healthy fallback lost: conn=%v err=%v calls=%d", conn, err, calls)
	}
}
