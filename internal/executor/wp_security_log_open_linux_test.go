//go:build linux

package executor

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestOpenSafeWPSecurityLogRejectsFIFOWithoutWaitingForWriter(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "access.log")
	if err := unix.Mkfifo(path, 0600); err != nil {
		t.Fatal(err)
	}
	assertSafeSecurityLogOpenRejectsWithoutBlocking(t, path)
}

func TestOpenSafeWPSecurityLogFIFOReplacementDoesNotBlock(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "access.log")
	if err := os.WriteFile(path, []byte("original\n"), 0600); err != nil {
		t.Fatal(err)
	}
	old := openWPSecurityLogFile
	t.Cleanup(func() { openWPSecurityLogFile = old })
	openWPSecurityLogFile = func(requested string) (*os.File, error) {
		if err := os.Remove(requested); err != nil {
			return nil, err
		}
		if err := unix.Mkfifo(requested, 0600); err != nil {
			return nil, err
		}
		return old(requested)
	}
	assertSafeSecurityLogOpenRejectsWithoutBlocking(t, path)
}

func assertSafeSecurityLogOpenRejectsWithoutBlocking(t *testing.T, path string) {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		f, err := openSafeWPSecurityLog(path, func(string) bool { return true })
		if f != nil {
			f.Close()
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("FIFO accepted as a regular security log")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("opening a FIFO security log waited for a writer")
	}
}
