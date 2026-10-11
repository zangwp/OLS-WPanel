//go:build linux

package executor

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/zangwp/OLS-WPanel/internal/models"
	"golang.org/x/sys/unix"
)

func siteBackupUID(site *models.Website) (int, error) {
	if site == nil || !olsSafeUserPattern.MatchString(site.SystemUser) {
		return 0, errors.New("站点用户无效")
	}
	data, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return 0, err
	}
	uid := 0
	matches := 0
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) != 7 || fields[0] != site.SystemUser {
			continue
		}
		matches++
		uid, err = strconv.Atoi(fields[2])
		if err != nil || uid <= 0 || (fields[6] != "/usr/sbin/nologin" && fields[6] != "/bin/false" && fields[6] != "/sbin/nologin") {
			return 0, errors.New("站点账户不是独占不可登录系统用户")
		}
	}
	if matches != 1 {
		return 0, errors.New("站点用户身份不唯一")
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) == 7 && fields[0] != site.SystemUser && fields[2] == strconv.Itoa(uid) {
			return 0, errors.New("站点 UID 被其他账户共用")
		}
	}
	return uid, nil
}

func siteBackupMountID(path string) (int, error) {
	data, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return 0, err
	}
	path = filepath.Clean(path)
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		point := strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, "\\").Replace(fields[4])
		point = filepath.Clean(point)
		if strings.HasPrefix(point, path+string(filepath.Separator)) {
			return 0, errors.New("站点目录包含外部挂载，无法安全冻结")
		}
		if point == path {
			id, err := strconv.Atoi(fields[0])
			if err != nil || id <= 0 {
				return 0, errors.New("挂载身份未知")
			}
			return id, nil
		}
	}
	return 0, nil
}

func validateSiteBackupUserAndFilesystem(ctx context.Context, site *models.Website) error {
	if os.Geteuid() != 0 {
		return errors.New("整站停写需要 Linux root 权限")
	}
	if _, err := siteBackupUID(site); err != nil {
		return err
	}
	if id, err := siteBackupMountID(site.WebRoot); err != nil || id != 0 {
		return errors.New("站点已有挂载或子挂载，不能覆盖管理员挂载")
	}
	for _, path := range []string{filepath.Join("/var/spool/cron/crontabs", site.SystemUser), filepath.Join("/var/spool/cron", site.SystemUser)} {
		data, err := os.ReadFile(path)
		if err != nil && !os.IsNotExist(err) {
			return err
		}
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "#") {
				return errors.New("站点系统用户有外部 crontab，请先停用")
			}
		}
	}
	paths := []string{"/etc/crontab"}
	entries, err := os.ReadDir("/etc/cron.d")
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			paths = append(paths, filepath.Join("/etc/cron.d", entry.Name()))
		}
	}
	for _, path := range paths {
		if filepath.Clean(path) == filepath.Clean(managedCronPath) {
			continue
		}
		data, err := os.ReadFile(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			if strings.Contains(line, site.SystemUser) || strings.Contains(line, site.WebRoot) || strings.Contains(line, site.Domain) || strings.Contains(line, site.DBName) {
				return errors.New("检测到该网站的外部系统计划任务，请先暂停")
			}
		}
	}
	var size int64
	count := 0
	err = filepath.WalkDir(site.WebRoot, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		count++
		if count > fileRestoreMaxEntries {
			return errors.New("站点文件数量超过安全恢复上限")
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.IsDir() && !info.Mode().IsRegular() {
			return errors.New("站点含链接或特殊文件，不能标记完整整站备份")
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return errors.New("站点文件身份未知")
		}
		if info.Mode().IsRegular() {
			if stat.Nlink != 1 {
				return errors.New("站点文件存在外部硬链接，不能安全停写")
			}
			if info.Size() < 0 || info.Size() > fileRestoreMaxBytes-size {
				return errors.New("站点文件大小超过安全恢复上限")
			}
			size += info.Size()
		}
		return nil
	})
	if err != nil {
		return err
	}
	return inspectSiteBackupExternalWriters(ctx, site, 0)
}

func siteBackupProcessUIDs(pid int) ([]int, error) {
	data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "status"))
	if err != nil {
		return nil, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "Uid:") {
			fields := strings.Fields(strings.TrimPrefix(line, "Uid:"))
			if len(fields) != 4 {
				return nil, errors.New("进程 UID 格式未知")
			}
			uids := make([]int, 4)
			for i, field := range fields {
				uids[i], err = strconv.Atoi(field)
				if err != nil {
					return nil, err
				}
			}
			return uids, nil
		}
	}
	return nil, errors.New("进程 UID 不可确认")
}

func siteBackupUserPIDs(ctx context.Context, uid int) ([]int, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	var pids []int
	for _, entry := range entries {
		if err = ctx.Err(); err != nil {
			return nil, err
		}
		pid, parseErr := strconv.Atoi(entry.Name())
		if parseErr != nil || pid <= 0 {
			continue
		}
		uids, readErr := siteBackupProcessUIDs(pid)
		if os.IsNotExist(readErr) {
			continue
		}
		if readErr != nil {
			return nil, readErr
		}
		for _, actual := range uids {
			if actual == uid {
				pids = append(pids, pid)
				break
			}
		}
	}
	return pids, nil
}

func stopSiteBackupUserProcesses(ctx context.Context, site *models.Website) error {
	uid, err := siteBackupUID(site)
	if err != nil {
		return err
	}
	pids, err := siteBackupUserPIDs(ctx, uid)
	if err != nil {
		return err
	}
	for _, pid := range pids {
		fd, err := unix.PidfdOpen(pid, 0)
		if errors.Is(err, unix.ESRCH) {
			continue
		}
		if err != nil {
			return errors.New("内核不支持可靠 PID 身份终止，无法证明站点已停写")
		}
		// Verify again after obtaining a non-reusable PID handle.
		uids, err := siteBackupProcessUIDs(pid)
		owned := false
		for _, actual := range uids {
			owned = owned || actual == uid
		}
		if err == nil && owned {
			err = unix.PidfdSendSignal(fd, unix.SIGKILL, nil, 0)
		}
		_ = unix.Close(fd)
		if err != nil && !os.IsNotExist(err) && !errors.Is(err, unix.ESRCH) {
			return err
		}
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		pids, err = siteBackupUserPIDs(ctx, uid)
		if err != nil {
			return err
		}
		if len(pids) == 0 {
			break
		}
		if time.Now().After(deadline) {
			return errors.New("站点 UID 进程仍在运行，不能创建完整备份")
		}
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
	return inspectSiteBackupExternalWriters(ctx, site, uid)
}

func ensureSiteBackupUserStopped(ctx context.Context, site *models.Website) error {
	uid, err := siteBackupUID(site)
	if err != nil {
		return err
	}
	pids, err := siteBackupUserPIDs(ctx, uid)
	if err != nil {
		return err
	}
	if len(pids) != 0 {
		return errors.New("维护期间出现新的站点 UID 进程，停止整站操作")
	}
	return inspectSiteBackupExternalWriters(ctx, site, uid)
}

func inspectSiteBackupExternalWriters(ctx context.Context, site *models.Website, allowedUID int) error {
	if allowedUID == 0 {
		uid, err := siteBackupUID(site)
		if err != nil {
			return err
		}
		allowedUID = uid
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if err = ctx.Err(); err != nil {
			return err
		}
		pid, parseErr := strconv.Atoi(entry.Name())
		if parseErr != nil || pid <= 0 {
			continue
		}
		uids, readErr := siteBackupProcessUIDs(pid)
		if os.IsNotExist(readErr) {
			continue
		}
		if readErr != nil {
			return readErr
		}
		owned := false
		for _, uid := range uids {
			owned = owned || uid == allowedUID
		}
		if owned {
			continue
		}
		proc := filepath.Join("/proc", entry.Name())
		for _, kind := range []string{"cwd", "exe"} {
			target, err := os.Readlink(filepath.Join(proc, kind))
			if os.IsNotExist(err) {
				continue
			}
			if err != nil {
				return err
			}
			if target == site.WebRoot || strings.HasPrefix(target, site.WebRoot+"/") {
				return errors.New("检测到网站目录中的外部进程，请先停止")
			}
		}
		fds, err := os.ReadDir(filepath.Join(proc, "fd"))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		for _, fd := range fds {
			target, err := os.Readlink(filepath.Join(proc, "fd", fd.Name()))
			if os.IsNotExist(err) {
				continue
			}
			if err != nil {
				return err
			}
			target = strings.TrimSuffix(target, " (deleted)")
			if target != site.WebRoot && !strings.HasPrefix(target, site.WebRoot+"/") {
				continue
			}
			info, err := os.ReadFile(filepath.Join(proc, "fdinfo", fd.Name()))
			if os.IsNotExist(err) {
				continue
			}
			if err != nil {
				return err
			}
			known := false
			for _, line := range strings.Split(string(info), "\n") {
				if strings.HasPrefix(line, "flags:") {
					flags, err := strconv.ParseUint(strings.TrimSpace(strings.TrimPrefix(line, "flags:")), 8, 64)
					if err != nil {
						return err
					}
					known = true
					if flags&uint64(unix.O_ACCMODE) != uint64(unix.O_RDONLY) {
						return errors.New("检测到网站目录外部写入文件句柄，请先停止")
					}
				}
			}
			if !known {
				return errors.New("外部文件句柄访问方式不可确认")
			}
		}
	}
	return nil
}

func mountSiteBackupReadOnly(path string) (int, error) {
	if id, err := siteBackupMountID(path); err != nil || id != 0 {
		return 0, errors.New("只读挂载前发现既有站点挂载")
	}
	if err := unix.Mount(path, path, "", unix.MS_BIND, ""); err != nil {
		return 0, fmt.Errorf("无法创建受控只读 bind mount，当前 VPS 不支持可靠整站停写: %w", err)
	}
	createdID, err := siteBackupMountID(path)
	if err != nil || createdID <= 0 {
		return 0, errors.New("本次 bind mount 身份无法确认，保留维护状态待核对")
	}
	if err := unix.Mount("", path, "", unix.MS_BIND|unix.MS_REMOUNT|unix.MS_RDONLY, ""); err != nil {
		return 0, errors.Join(err, unmountSiteBackupReadOnly(path, createdID))
	}
	var stat unix.Statfs_t
	if err := unix.Statfs(path, &stat); err != nil || stat.Flags&unix.ST_RDONLY == 0 {
		return 0, errors.Join(errors.New("网站只读挂载未通过内核核验"), unmountSiteBackupReadOnly(path, createdID))
	}
	id, err := siteBackupMountID(path)
	if err != nil || id != createdID {
		return 0, errors.New("本次只读挂载身份已变化，保留维护状态待核对")
	}
	return id, nil
}

func unmountSiteBackupReadOnly(path string, expectedID int) error {
	id, err := siteBackupMountID(path)
	if err != nil {
		return err
	}
	if id == 0 {
		return nil
	}
	if expectedID <= 0 || id != expectedID {
		return errors.New("只读挂载身份未持久确认或已变化，拒绝卸载管理员挂载")
	}
	if err = unix.Unmount(path, 0); err != nil {
		return err
	}
	id, err = siteBackupMountID(path)
	if err != nil || id != 0 {
		return errors.New("网站只读挂载未解除")
	}
	return nil
}
