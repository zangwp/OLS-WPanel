package executor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var backupDependencyPreferencesRead = readBackupDependencyAPTPreferences

const backupDependencyPreferenceLimit = 4 << 20

var backupDependencyPreferenceFilenameRE = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)

func readBackupDependencyAPTPreferences(ctx context.Context) (string, error) {
	return backupDependencyPreferenceSnapshot(ctx, backupDependencyReadCommand, fileOwnerIDs, 0, string(filepath.Separator))
}

func backupDependencyPreferenceSnapshot(ctx context.Context, readCommand func(context.Context, string, ...string) ([]byte, error), owner func(os.FileInfo) (int, int, error), expectedUID int, trustedScope string) (string, error) {
	output, err := readCommand(ctx, "apt-config", "shell", "MAIN", "Dir::Etc::preferences/f", "PARTS", "Dir::Etc::preferencesparts/d")
	if err != nil {
		return "", fmt.Errorf("APT preference configuration could not be checked: %w", err)
	}
	main, parts, err := parseBackupDependencyPreferencePaths(output)
	if err != nil {
		return "", err
	}
	var snapshot strings.Builder
	appendFile := func(name string, required bool) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		info, err := validateBackupDependencyPreferencePath(name, "file", owner, expectedUID, trustedScope)
		if err != nil {
			return err
		}
		if info == nil { // A missing main preferences file is normal.
			if required {
				return errors.New("APT preference fragment disappeared while being read")
			}
			return nil
		}
		file, err := os.Open(name)
		if err != nil {
			return errors.New("APT preferences could not be read")
		}
		defer file.Close()
		opened, err := file.Stat()
		if err != nil || !os.SameFile(info, opened) {
			return errors.New("APT preferences changed while being read")
		}
		content, err := io.ReadAll(io.LimitReader(file, int64(backupDependencyPreferenceLimit-snapshot.Len()+1)))
		if err != nil || len(content) > backupDependencyPreferenceLimit-snapshot.Len()-2 {
			return errors.New("APT preference configuration exceeds the supported size")
		}
		after, err := file.Stat()
		if err != nil || !os.SameFile(opened, after) || opened.Size() != after.Size() || !opened.ModTime().Equal(after.ModTime()) {
			return errors.New("APT preferences changed while being read")
		}
		snapshot.Write(content)
		snapshot.WriteString("\n\n")
		return nil
	}
	if main != "/dev/null" {
		if err := appendFile(main, false); err != nil {
			return "", err
		}
	}
	if parts != "/dev/null" {
		info, err := validateBackupDependencyPreferencePath(parts, "directory", owner, expectedUID, trustedScope)
		if err != nil {
			return "", err
		}
		if info != nil {
			entries, err := os.ReadDir(parts) // os.ReadDir returns filename order, as APT requires.
			if err != nil || len(entries) > 256 {
				return "", errors.New("APT preference fragments could not be checked")
			}
			for _, entry := range entries {
				name := entry.Name()
				// Match APT's documented fragment naming policy. Files such as
				// *.save and editor backups are ignored by APT as well.
				if strings.HasPrefix(name, ".") || !backupDependencyPreferenceFilenameRE.MatchString(name) || (filepath.Ext(name) != "" && filepath.Ext(name) != ".pref") {
					continue
				}
				if err := appendFile(filepath.Join(parts, name), true); err != nil {
					return "", err
				}
			}
		}
	}
	return snapshot.String(), nil
}

func parseBackupDependencyPreferencePaths(output []byte) (string, string, error) {
	fail := func() (string, string, error) {
		return "", "", errors.New("APT preference paths use an unsupported configuration format")
	}
	if len(output) == 0 || len(output) > 16*1024 || output[len(output)-1] != '\n' {
		return fail()
	}
	values := map[string]string{}
	for _, line := range strings.Split(strings.TrimSuffix(string(output), "\n"), "\n") {
		key, value, found := strings.Cut(line, "='")
		if !found || (key != "MAIN" && key != "PARTS") || len(value) < 1 || value[len(value)-1] != '\'' {
			return fail()
		}
		value = value[:len(value)-1]
		if _, duplicate := values[key]; duplicate || !filepath.IsAbs(value) || strings.ContainsAny(value, "'\\") || strings.IndexFunc(value, func(r rune) bool { return r < 32 || r == 127 }) >= 0 {
			return fail()
		}
		values[key] = filepath.Clean(value)
	}
	if len(values) != 2 {
		return fail()
	}
	return values["MAIN"], values["PARTS"], nil
}

func validateBackupDependencyPreferencePath(name, kind string, owner func(os.FileInfo) (int, int, error), expectedUID int, scope string) (os.FileInfo, error) {
	fail := func() (os.FileInfo, error) {
		return nil, errors.New("APT preference path ownership, type or permissions could not be verified")
	}
	name, scope = filepath.Clean(name), filepath.Clean(scope)
	relative, err := filepath.Rel(scope, name)
	if err != nil || !filepath.IsAbs(name) || !filepath.IsAbs(scope) || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return fail()
	}
	var target os.FileInfo
	for current := name; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if os.IsNotExist(err) && current == name {
			// Validate the parent before accepting an absent optional file.
		} else if err != nil {
			return fail()
		} else {
			uid, _, ownerErr := owner(info)
			if ownerErr != nil || uid != expectedUID || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 {
				return fail()
			}
			if current == name {
				if (kind == "file" && !info.Mode().IsRegular()) || (kind == "directory" && !info.IsDir()) {
					return fail()
				}
				target = info
			} else if !info.IsDir() {
				return fail()
			}
		}
		if current == scope {
			break
		}
		if filepath.Dir(current) == current {
			return fail()
		}
	}
	return target, nil
}
