//go:build linux

package executor

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWPPanelAccessUnixPeerUIDComesFromKernel(t *testing.T) {
	listener, err := net.Listen("unix", filepath.Join(t.TempDir(), "peer.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	got := make(chan int, 1)
	failures := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			failures <- err
			return
		}
		defer conn.Close()
		uid, err := wpPanelAccessUnixPeerUID(conn)
		if err != nil {
			failures <- err
			return
		}
		got <- uid
	}()
	conn, err := net.Dial("unix", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	select {
	case uid := <-got:
		if uid != os.Getuid() {
			t.Fatalf("kernel peer uid=%d, process=%d", uid, os.Getuid())
		}
	case err := <-failures:
		t.Fatal(err)
	case <-time.After(2 * time.Second):
		t.Fatal("peer credentials timed out")
	}
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	if _, err := wpPanelAccessUnixPeerUID(left); err == nil {
		t.Fatal("non-Unix connection was accepted as trusted peer")
	}
}
