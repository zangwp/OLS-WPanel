package executor

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSSHConfirmationRequiresProofBeforeMutation(t *testing.T) {
	oldMove, oldCommand := sshMove, portCommand
	defer func() { sshMove = oldMove; portCommand = oldCommand }()
	sshMove.Token = "test"
	sshMove.Deadline = time.Now().Add(time.Minute)
	sshMove.dir = t.TempDir()
	portCommand = func(context.Context, string, ...string) (string, error) {
		t.Fatal("mutation before new-session proof")
		return "", nil
	}
	if e := ConfirmSSHPortChange("test"); e == nil || !strings.Contains(e.Error(), "验证命令") {
		t.Fatalf("proof bypassed: %v", e)
	}
	if e := os.WriteFile(filepath.Join(sshMove.dir, "verified"), []byte("wrong-token"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := ConfirmSSHPortChange("test"); e == nil {
		t.Fatal("wrong proof accepted")
	}
	sshMove.Deadline = time.Now().Add(-time.Second)
	if e := ConfirmSSHPortChange("test"); e == nil {
		t.Fatal("expired confirmation accepted")
	}
}

func TestSSHConfirmationRejectsConcurrentConfigEdit(t *testing.T) {
	oldMove, oldPath, oldCommand := sshMove, sshConfigPath, portCommand
	defer func() { sshMove = oldMove; sshConfigPath = oldPath; portCommand = oldCommand }()
	sshMove.Token = "test"
	sshMove.Deadline = time.Now().Add(time.Minute)
	sshMove.dir = t.TempDir()
	sshMove.expectedConfig = "expected"
	sshConfigPath = filepath.Join(sshMove.dir, "config")
	if e := os.WriteFile(sshConfigPath, []byte("edited externally"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(sshMove.dir, "verified"), []byte("test"), 0600); e != nil {
		t.Fatal(e)
	}
	portCommand = func(context.Context, string, ...string) (string, error) {
		t.Fatal("mutation after concurrent configuration edit")
		return "", nil
	}
	if e := ConfirmSSHPortChange("test"); e == nil || !strings.Contains(e.Error(), "其他操作") {
		t.Fatalf("edit ignored: %v", e)
	}
}
