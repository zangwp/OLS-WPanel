package executor

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/zangwp/OLS-WPanel/internal/models"
)

// SiteBackupExport pins verified local artifact descriptors. The uncompressed
// outer tar does not recompress its gzip components or buffer a whole backup.
type SiteBackupExport interface {
	io.Closer
	Filename() string
	Size() int64
	Write(context.Context, io.Writer) error
}

type siteBackupExportEntry struct {
	name   string
	size   int64
	sha256 string
	file   *os.File
	data   []byte
}

type siteBackupExport struct {
	filename, prefix string
	created          time.Time
	entries          []siteBackupExportEntry
	size             int64
	release          func()
}

var siteBackupExportSlots = make(chan struct{}, 2)

func (bundle *siteBackupExport) Filename() string { return bundle.filename }
func (bundle *siteBackupExport) Size() int64      { return bundle.size }
func (bundle *siteBackupExport) Close() error {
	var result error
	for index := range bundle.entries {
		if file := bundle.entries[index].file; file != nil {
			result = errors.Join(result, file.Close())
			bundle.entries[index].file = nil
		}
	}
	if bundle.release != nil {
		bundle.release()
		bundle.release = nil
	}
	return result
}

// PrepareSiteBackupExport validates ownership and hashes before HTTP headers
// are sent. Only complete backup points are exportable, never recovery journals.
func PrepareSiteBackupExport(ctx context.Context, site *models.Website, id string) (SiteBackupExport, error) {
	manifest, dir, err := readSiteBackupManifest(ctx, site, id)
	if err != nil {
		return nil, err
	}
	return prepareSiteBackupExport(ctx, site, manifest, dir)
}

func prepareSiteBackupExport(ctx context.Context, site *models.Website, manifest *models.SiteBackupManifest, dir string) (SiteBackupExport, error) {
	if site == nil || manifest == nil || !validSiteBackupID(manifest.ID) || manifest.SiteID != site.ID || manifest.Domain != site.Domain {
		return nil, errors.New("整站备份不属于当前网站")
	}
	if manifest.Operation != "create" || manifest.State != "complete" || manifest.RequiresAttention || manifest.Consistency != "controlled_quiescence" {
		return nil, errors.New("只有本地完整且无需处理现场的整站备份可以导出")
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case siteBackupExportSlots <- struct{}{}:
	default:
		return nil, errors.New("已有完整备份导出正在进行，请完成后重试")
	}
	bundle := &siteBackupExport{filename: site.Domain + "_" + manifest.ID + "_site-backup.tar", prefix: manifest.ID + "/", created: manifest.CreatedAt.UTC().Truncate(time.Second)}
	bundle.release = func() { <-siteBackupExportSlots }
	keep := false
	defer func() {
		if !keep {
			_ = bundle.Close()
		}
	}()
	for _, item := range []struct {
		artifact models.SiteBackupArtifact
		name     string
	}{{manifest.Files, "files.tar.gz"}, {manifest.Database, "database.sql.gz"}} {
		if item.artifact.Name != item.name || item.artifact.Size <= 0 || item.artifact.Size > fileRestoreMaxBytes || len(item.artifact.SHA256) != 64 {
			return nil, errors.New("整站备份组件记录无效，未生成导出包")
		}
		if _, err := hex.DecodeString(item.artifact.SHA256); err != nil {
			return nil, errors.New("整站备份组件指纹无效")
		}
		file, err := openFileRestoreArchive(filepath.Join(dir, item.name), item.artifact.Size)
		if err != nil {
			return nil, errors.New("本地整站备份组件缺失或已变化")
		}
		bundle.entries = append(bundle.entries, siteBackupExportEntry{name: item.name, size: item.artifact.Size, sha256: item.artifact.SHA256, file: file})
		hash := sha256.New()
		n, err := copyWithContext(ctx, hash, io.LimitReader(file, item.artifact.Size+1))
		if err != nil {
			return nil, err
		}
		if n != item.artifact.Size || hex.EncodeToString(hash.Sum(nil)) != item.artifact.SHA256 {
			return nil, errors.New("整站备份组件 SHA-256 不匹配，未生成导出包")
		}
		if _, err = file.Seek(0, io.SeekStart); err != nil {
			return nil, err
		}
	}
	// Export only the recovery point's portable binding and component hashes.
	// Runtime vhost text, maintenance ownership, safety paths and diagnostic
	// messages can contain host secrets and are not needed to restore a point.
	portable := models.SiteBackupManifest{Version: manifest.Version,
		SiteBackup: models.SiteBackup{ID: manifest.ID, SiteID: manifest.SiteID, CreatedAt: manifest.CreatedAt, State: "complete", LocalExists: true, FileSize: manifest.Files.Size, DBSize: manifest.Database.Size, Consistency: manifest.Consistency},
		Domain:     manifest.Domain, Aliases: manifest.Aliases, WebRoot: manifest.WebRoot, SystemUser: manifest.SystemUser,
		DBName: manifest.DBName, DBUser: manifest.DBUser, TablePrefix: manifest.TablePrefix, Files: manifest.Files, Database: manifest.Database,
		Operation: "create", Phase: "completed", UpdatedAt: manifest.UpdatedAt}
	data, err := json.MarshalIndent(portable, "", "  ")
	if err != nil {
		return nil, err
	}
	data = append(data, '\n')
	if len(data) > 1<<20 {
		return nil, errors.New("整站备份导出清单超过大小上限")
	}
	manifestHash := sha256.Sum256(data)
	bundle.entries = append(bundle.entries, siteBackupExportEntry{name: "manifest.json", size: int64(len(data)), sha256: hex.EncodeToString(manifestHash[:]), data: data})
	var checksums bytes.Buffer
	for _, entry := range bundle.entries {
		fmt.Fprintf(&checksums, "%s  %s\n", entry.sha256, entry.name)
	}
	bundle.entries = append(bundle.entries, siteBackupExportEntry{name: "SHA256SUMS", size: int64(checksums.Len()), data: checksums.Bytes()})
	bundle.size = 1024 // Two terminating tar blocks; all four GNU headers are fixed-size.
	for _, entry := range bundle.entries {
		bundle.size += 512 + ((entry.size+511)/512)*512
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	keep = true
	return bundle, nil
}

func (bundle *siteBackupExport) Write(ctx context.Context, destination io.Writer) error {
	archive := tar.NewWriter(destination)
	for _, entry := range bundle.entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := archive.WriteHeader(&tar.Header{Name: bundle.prefix + entry.name, Size: entry.size, Mode: 0600, ModTime: bundle.created, Typeflag: tar.TypeReg, Format: tar.FormatGNU}); err != nil {
			return err
		}
		var reader io.Reader = bytes.NewReader(entry.data)
		if entry.file != nil {
			info, err := entry.file.Stat()
			if err != nil || !info.Mode().IsRegular() || info.Size() != entry.size {
				return errors.New("整站备份组件在导出期间发生变化，下载未完成")
			}
			reader = entry.file
		} else if entry.data == nil {
			return errors.New("整站备份导出文件已关闭")
		}
		hash := sha256.New()
		n, err := copyWithContext(ctx, io.MultiWriter(archive, hash), io.LimitReader(reader, entry.size+1))
		if err != nil {
			return err
		}
		if n != entry.size || (entry.sha256 != "" && hex.EncodeToString(hash.Sum(nil)) != entry.sha256) {
			return errors.New("整站备份在传输期间校验失败，下载未完成")
		}
	}
	return archive.Close()
}
