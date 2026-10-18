//go:build linux

package executor

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/zangwp/OLS-WPanel/internal/config"
	"golang.org/x/sys/unix"
)

const olsAccessACLAttribute = "system.posix_acl_access"

var lookupOLSWebAdminUser = user.Lookup

func olsWebAdminUID() (uint32, bool, error) {
	account, err := lookupOLSWebAdminUser("lsadm")
	if err != nil {
		var missing user.UnknownUserError
		if errors.As(err, &missing) {
			return 0, false, nil
		}
		return 0, false, err
	}
	id, err := strconv.ParseUint(account.Uid, 10, 32)
	if err != nil || id == 0 || id == uint64(olsACLNoID) {
		return 0, false, fmt.Errorf("invalid WebAdmin user ID")
	}
	return uint32(id), true, nil
}

type olsWebAdminConfigPaths struct {
	root, main, registry, available, fallback string
}

func currentOLSWebAdminConfigPaths() olsWebAdminConfigPaths {
	paths := currentOLSRuntimePaths()
	_, fallback := olsDefaultVHostPaths(paths)
	available := filepath.Join(filepath.Dir(paths.managed), "sites-available")
	if config.AppConfig != nil && strings.TrimSpace(config.AppConfig.Paths.OLSVHostsAvailable) != "" {
		available = config.AppConfig.Paths.OLSVHostsAvailable
	}
	return olsWebAdminConfigPaths{filepath.Clean(paths.root), filepath.Clean(paths.mainConfig), filepath.Clean(paths.managed), filepath.Clean(available), filepath.Clean(fallback)}
}

func (paths olsWebAdminConfigPaths) contains(path string) bool {
	if !filepath.IsAbs(paths.root) || !filepath.IsAbs(path) || paths.root == "/" {
		return false
	}
	rel, err := filepath.Rel(paths.root, path)
	return err == nil && rel != "." && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func (paths olsWebAdminConfigPaths) recognizes(path string, data []byte) bool {
	path = filepath.Clean(path)
	if !paths.contains(path) {
		return false
	}
	switch path {
	case paths.main, paths.fallback:
		return true
	case paths.registry:
		return bytes.HasPrefix(data, []byte("# OLS WPanel managed OpenLiteSpeed registry. DO NOT EDIT.\n"))
	}
	if filepath.Dir(path) == paths.available && strings.HasSuffix(path, ".conf") {
		_, err := parseOLSVHostMetadata(string(data), path)
		return err == nil
	}
	return false
}

// Open every component without following links. Managed directories may be
// owned by root or the WebAdmin administrator, never a website account.
func openOLSWebAdminConfig(path string, paths olsWebAdminConfigPaths, uid uint32, directory bool) (*os.File, error) {
	path = filepath.Clean(path)
	if path != paths.root && !paths.contains(path) {
		return nil, fmt.Errorf("WebAdmin config path is outside the OLS root")
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	current := "/"
	for index, part := range parts {
		flags := unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NONBLOCK
		isDir := index < len(parts)-1 || directory
		if isDir {
			flags |= unix.O_DIRECTORY
		}
		next, openErr := unix.Openat(fd, part, flags, 0)
		unix.Close(fd)
		if openErr != nil {
			return nil, openErr
		}
		fd = next
		current = filepath.Join(current, part)
		if current == paths.root || paths.contains(current) {
			var stat unix.Stat_t
			if err = unix.Fstat(fd, &stat); err != nil {
				unix.Close(fd)
				return nil, err
			}
			ownerAllowed := stat.Uid == 0 || stat.Uid == uid && (isDir || current == paths.main)
			kindAllowed := stat.Mode&unix.S_IFMT == unix.S_IFREG && stat.Nlink == 1
			if isDir {
				kindAllowed = stat.Mode&unix.S_IFMT == unix.S_IFDIR
			}
			if !ownerAllowed || !kindAllowed || stat.Mode&0022 != 0 {
				unix.Close(fd)
				return nil, fmt.Errorf("unsafe WebAdmin config ownership or permissions: %s", current)
			}
		}
	}
	return os.NewFile(uintptr(fd), path), nil
}

func readOLSAccessACL(file *os.File) ([]byte, error) {
	data := make([]byte, 65536)
	size, err := unix.Fgetxattr(int(file.Fd()), olsAccessACLAttribute, data)
	if errors.Is(err, unix.ENODATA) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return data[:size], nil
}

func writeOLSAccessACL(file *os.File, value []byte) error {
	if len(value) == 0 {
		err := unix.Fremovexattr(int(file.Fd()), olsAccessACLAttribute)
		if errors.Is(err, unix.ENODATA) {
			return nil
		}
		return err
	}
	return unix.Fsetxattr(int(file.Fd()), olsAccessACLAttribute, value, 0)
}

type olsWebAdminACLChange struct {
	file          *os.File
	before, after []byte
	mode          os.FileMode
}

func prepareOLSWebAdminACL(file *os.File, uid uint32, permission uint16, source []byte) (olsWebAdminACLChange, error) {
	change := olsWebAdminACLChange{file: file}
	info, err := file.Stat()
	if err != nil {
		return change, err
	}
	owner, _, err := fileOwnerIDs(info)
	if err != nil {
		return change, err
	}
	change.mode = info.Mode().Perm()
	change.before, err = readOLSAccessACL(file)
	if err != nil {
		return change, err
	}
	if source == nil {
		source = change.before
	}
	change.after, err = olsWebAdminACL(source, info.Mode(), uint32(owner), uid, permission)
	return change, err
}

func applyOLSWebAdminACLChanges(changes []olsWebAdminACLChange) error {
	for index, change := range changes {
		if bytes.Equal(change.before, change.after) {
			continue
		}
		if err := writeOLSAccessACL(change.file, change.after); err != nil {
			failures := []error{fmt.Errorf("grant WebAdmin config read access: %w", err)}
			for rollback := index - 1; rollback >= 0; rollback-- {
				previous := changes[rollback]
				if bytes.Equal(previous.before, previous.after) {
					continue
				}
				if restoreErr := writeOLSAccessACL(previous.file, previous.before); restoreErr != nil {
					failures = append(failures, restoreErr)
				} else if len(previous.before) == 0 {
					// Removing an extended ACL retains its mask in the mode bits.
					if restoreErr := previous.file.Chmod(previous.mode); restoreErr != nil {
						failures = append(failures, restoreErr)
					}
				}
			}
			return errors.Join(failures...)
		}
	}
	return nil
}

func prepareOLSWebAdminDirectories(paths olsWebAdminConfigPaths, target string, uid uint32) ([]olsWebAdminACLChange, error) {
	var changes []olsWebAdminACLChange
	for dir := filepath.Dir(target); dir == paths.root || paths.contains(dir); dir = filepath.Dir(dir) {
		file, err := openOLSWebAdminConfig(dir, paths, uid, true)
		if err != nil {
			closeOLSWebAdminACLChanges(changes)
			return nil, err
		}
		change, err := prepareOLSWebAdminACL(file, uid, 1, nil)
		if err != nil {
			file.Close()
			closeOLSWebAdminACLChanges(changes)
			return nil, err
		}
		changes = append(changes, change)
	}
	return changes, nil
}

func closeOLSWebAdminACLChanges(changes []olsWebAdminACLChange) {
	for _, change := range changes {
		change.file.Close()
	}
}

// Called before rename so a failed ACL grant leaves the old configuration in
// place. Only recognized OLS configuration files receive WebAdmin access.
func prepareOLSWebAdminReplacement(path string, file *os.File, data []byte) error {
	paths := currentOLSWebAdminConfigPaths()
	if !paths.recognizes(path, data) {
		return nil
	}
	uid, exists, err := olsWebAdminUID()
	if err != nil || !exists {
		return err
	}
	var originalACL []byte
	original, err := openOLSWebAdminConfig(path, paths, uid, false)
	if err == nil {
		originalACL, err = readOLSAccessACL(original)
		original.Close()
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	changes, err := prepareOLSWebAdminDirectories(paths, path, uid)
	if err != nil {
		return err
	}
	defer closeOLSWebAdminACLChanges(changes)
	change, err := prepareOLSWebAdminACL(file, uid, 4, originalACL)
	if err != nil {
		return err
	}
	return applyOLSWebAdminACLChanges(append(changes, change))
}

// Backfill existing installations once at startup. No recursive permission
// changes, default ACLs, service reloads, or external ACL utilities are needed.
func EnsureOLSWebAdminConfigReadAccess() error {
	uid, exists, err := olsWebAdminUID()
	if err != nil || !exists {
		return err
	}
	paths := currentOLSWebAdminConfigPaths()
	registry, err := openOLSWebAdminConfig(paths.registry, paths, uid, false)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	data, readErr := io.ReadAll(io.LimitReader(registry, 2<<20+1))
	registry.Close()
	if readErr != nil {
		return readErr
	}
	if len(data) > 2<<20 || !paths.recognizes(paths.registry, data) {
		return fmt.Errorf("cannot verify panel-owned OLS registry")
	}
	targets := []string{paths.main, paths.registry, paths.fallback}
	available, err := openOLSWebAdminConfig(paths.available, paths, uid, true)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err == nil {
		entries, readErr := available.ReadDir(-1)
		available.Close()
		if readErr != nil {
			return readErr
		}
		for _, entry := range entries {
			if strings.HasSuffix(entry.Name(), ".conf") {
				targets = append(targets, filepath.Join(paths.available, entry.Name()))
			}
		}
	}
	var changes []olsWebAdminACLChange
	defer func() { closeOLSWebAdminACLChanges(changes) }()
	seenDirectories := map[string]bool{}
	for _, target := range targets {
		file, openErr := openOLSWebAdminConfig(target, paths, uid, false)
		if errors.Is(openErr, os.ErrNotExist) {
			continue
		}
		if openErr != nil {
			return openErr
		}
		content, readErr := io.ReadAll(io.LimitReader(file, 2<<20+1))
		if readErr != nil || len(content) > 2<<20 || !paths.recognizes(target, content) {
			file.Close()
			return fmt.Errorf("cannot verify managed OLS config: %s", target)
		}
		change, err := prepareOLSWebAdminACL(file, uid, 4, nil)
		if err != nil {
			file.Close()
			return err
		}
		changes = append(changes, change)
		directories, err := prepareOLSWebAdminDirectories(paths, target, uid)
		if err != nil {
			return err
		}
		for _, directory := range directories {
			name := directory.file.Name()
			if seenDirectories[name] {
				directory.file.Close()
				continue
			}
			seenDirectories[name] = true
			changes = append(changes, directory)
		}
	}
	return applyOLSWebAdminACLChanges(changes)
}
