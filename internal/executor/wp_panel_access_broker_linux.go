//go:build linux

package executor

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

type wpPanelAccessBroker struct {
	server   *http.Server
	listener net.Listener
	stop     chan struct{}
	once     sync.Once
}

func (b *wpPanelAccessBroker) Close() error {
	var err error
	b.once.Do(func() {
		wpPanelAccessBrokerReady.Store(false)
		close(b.stop)
		DefaultWPPanelAccessTokens.Revoke(0, "")
		err = b.server.Close()
	})
	return err
}

func StartWPPanelAccessBroker(ctx context.Context, redeem WPPanelAccessRedeemer) (io.Closer, error) {
	if os.Geteuid() != 0 || redeem == nil {
		return nil, errors.New("WordPress login broker requires root")
	}
	dir := filepath.Dir(WPPanelAccessSocketPath)
	if err := os.Mkdir(dir, 0755); err != nil && !os.IsExist(err) {
		return nil, err
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 {
		return nil, errors.New("unsafe WordPress login socket directory")
	}
	uid, _, err := fileOwnerIDs(info)
	if err != nil || uid != 0 {
		return nil, errors.New("unsafe WordPress login socket ownership")
	}
	if info, err := os.Lstat(WPPanelAccessSocketPath); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, errors.New("WordPress login socket path occupied")
		}
		uid, _, ownerErr := fileOwnerIDs(info)
		if ownerErr != nil || uid != 0 {
			return nil, errors.New("unsafe WordPress login socket ownership")
		}
		conn, dialErr := net.DialTimeout("unix", WPPanelAccessSocketPath, time.Second)
		if dialErr == nil {
			conn.Close()
			return nil, errors.New("WordPress login broker already running")
		}
		if err := os.Remove(WPPanelAccessSocketPath); err != nil {
			return nil, err
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	listener, err := net.Listen("unix", WPPanelAccessSocketPath)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(WPPanelAccessSocketPath, 0666); err != nil {
		listener.Close()
		return nil, err
	}
	server := &http.Server{Handler: wpPanelAccessBrokerHandler(redeem), ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 3 * time.Second, MaxHeaderBytes: 4096}
	server.ConnContext = func(ctx context.Context, conn net.Conn) context.Context {
		uid, err := wpPanelAccessUnixPeerUID(conn)
		if err != nil {
			return ctx
		}
		return context.WithValue(ctx, wpPanelAccessPeerUIDKey{}, uid)
	}
	b := &wpPanelAccessBroker{server: server, listener: listener, stop: make(chan struct{})}
	wpPanelAccessBrokerReady.Store(true)
	go func() { _ = server.Serve(listener); _ = b.Close() }()
	go func() {
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				_ = b.Close()
				return
			case <-b.stop:
				return
			case <-ticker.C:
				DefaultWPPanelAccessTokens.CleanExpired()
			}
		}
	}()
	return b, nil
}

func wpPanelAccessUnixPeerUID(conn net.Conn) (int, error) {
	unix, ok := conn.(*net.UnixConn)
	if !ok {
		return -1, errors.New("WordPress login requires a Unix peer")
	}
	raw, err := unix.SyscallConn()
	if err != nil {
		return -1, err
	}
	var peer *syscall.Ucred
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		peer, credErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return -1, err
	}
	if credErr != nil {
		return -1, credErr
	}
	if peer == nil {
		return -1, errors.New("WordPress login peer unavailable")
	}
	return int(peer.Uid), nil
}
