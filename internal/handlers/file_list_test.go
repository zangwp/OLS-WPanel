package handlers

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
	"time"
)

type listTestInfo struct {
	name      string
	size      int64
	directory bool
}

func (f listTestInfo) Name() string { return f.name }
func (f listTestInfo) Size() int64  { return f.size }
func (f listTestInfo) Mode() fs.FileMode {
	if f.directory {
		return fs.ModeDir | 0700
	}
	return 0600
}
func (f listTestInfo) ModTime() time.Time { return time.Unix(1700000000+f.size, 0) }
func (f listTestInfo) IsDir() bool        { return f.directory }
func (f listTestInfo) Sys() any           { return nil }

type listTestEntry struct {
	listTestInfo
	infos *int
	fail  bool
}

func (e listTestEntry) Type() fs.FileMode { return e.Mode().Type() }
func (e listTestEntry) Info() (fs.FileInfo, error) {
	*e.infos++
	if e.fail {
		return nil, os.ErrNotExist
	}
	return e.listTestInfo, nil
}

type listTestDirectory struct {
	fs.ReadDirFile
	entries []fs.DirEntry
	reads   int
}

func (d *listTestDirectory) ReadDir(n int) ([]fs.DirEntry, error) {
	d.reads++
	if len(d.entries) == 0 {
		return nil, io.EOF
	}
	if n > len(d.entries) {
		n = len(d.entries)
	}
	batch := d.entries[:n]
	d.entries = d.entries[n:]
	return batch, nil
}
func fileListFixture() (*listTestDirectory, *int) {
	infos := new(int)
	dir := &listTestDirectory{}
	for i, name := range []string{"z.bin", "a.txt", "Folder", "A.txt", "plain", "b.txt"} {
		dir.entries = append(dir.entries, listTestEntry{listTestInfo{name: name, size: int64(6 - i), directory: name == "Folder"}, infos, false})
	}
	return dir, infos
}

func TestBoundedFileListPreservesSortAndPageWhileReadingOnlyNeededMetadata(t *testing.T) {
	for _, sortBy := range []string{"name", "type", "size", "time", "unknown"} {
		for _, sortDir := range []string{"asc", "desc"} {
			t.Run(sortBy+"/"+sortDir, func(t *testing.T) {
				dir, infos := fileListFixture()
				baseline := []fileEntry{}
				for _, entry := range dir.entries {
					item := fileEntry{Name: entry.Name(), IsDir: entry.IsDir()}
					if err := fillFileListMetadata(&item, entry); err != nil {
						t.Fatal(err)
					}
					baseline = append(baseline, item)
				}
				*infos = 0
				sort.Slice(baseline, func(i, j int) bool { return baseline[i].Name < baseline[j].Name })
				sortFileEntries(baseline, sortBy, sortDir)
				want, _, _ := paginateFileEntries(baseline, 2, 2)
				got, err := readFileList(context.Background(), dir, fileListOptions{page: 2, perPage: 2, sortBy: sortBy, sortDir: sortDir, paged: true})
				if err != nil || !reflect.DeepEqual(got.files, want) || got.total != 6 || got.page != 2 || got.totalPages != 3 {
					t.Fatalf("got=%+v want=%+v err=%v", got, want, err)
				}
				wantInfos := 2
				if sortBy == "size" || sortBy == "time" {
					wantInfos = 6
				}
				if *infos != wantInfos {
					t.Fatalf("metadata calls=%d want=%d", *infos, wantInfos)
				}
			})
		}
	}
}

func TestBoundedFileListRejectsOversizeInsteadOfReturningPartialSuccess(t *testing.T) {
	dir, infos := fileListFixture()
	got, err := readFileList(context.Background(), dir, fileListOptions{page: 1, perPage: 2, sortBy: "name", paged: true, entryLimit: 5})
	if !errors.Is(err, errFileListTooLarge) || len(got.files) != 0 || *infos != 0 {
		t.Fatalf("got=%+v err=%v metadata=%d", got, err, *infos)
	}
}

func TestBoundedFileListCancellationAndMissingMetadataDoNotFabricateTotals(t *testing.T) {
	dir, infos := fileListFixture()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got, err := readFileList(ctx, dir, fileListOptions{paged: true})
	if !errors.Is(err, context.Canceled) || len(got.files) != 0 || dir.reads != 0 || *infos != 0 {
		t.Fatalf("got=%+v err=%v reads=%d", got, err, dir.reads)
	}
	dir, infos = fileListFixture()
	entry := dir.entries[2].(listTestEntry)
	entry.fail = true
	dir.entries[2] = entry
	got, err = readFileList(context.Background(), dir, fileListOptions{page: 1, perPage: 2, sortBy: "name", paged: true})
	if !errors.Is(err, errFileListChanged) || len(got.files) != 0 {
		t.Fatalf("missing entry returned partial listing: %+v %v", got, err)
	}
}

func TestBoundedFileListLegacyAndEmptyContracts(t *testing.T) {
	dir, infos := fileListFixture()
	got, err := readFileList(context.Background(), dir, fileListOptions{})
	if err != nil || len(got.files) != 6 || got.perPage != 6 || got.totalPages != 1 || *infos != 6 {
		t.Fatalf("legacy result=%+v err=%v infos=%d", got, err, *infos)
	}
	got, err = readFileList(context.Background(), &listTestDirectory{}, fileListOptions{paged: true, page: 9, perPage: 50})
	if err != nil || got.files == nil || got.total != 0 || got.page != 1 || got.totalPages != 1 {
		t.Fatalf("empty=%+v err=%v", got, err)
	}
}

func TestBoundedFileListAndSearchUseRealDirectoryWithDifferentBudgets(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"z-noise", "a-match", "b-noise", "c-noise"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(name), 0600); err != nil {
			t.Fatal(err)
		}
	}
	dir, err := os.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	if _, err := readFileList(context.Background(), dir, fileListOptions{paged: true, entryLimit: 3}); !errors.Is(err, errFileListTooLarge) {
		t.Fatalf("large directory err=%v", err)
	}
	search, err := searchFileTreeWithLimits(context.Background(), root, root, "match", false, "name", "asc", 1, 50, fileSearchLimits{MaxScanned: 10, MaxMatches: 10})
	if err != nil || search.Truncated || len(search.Files) != 1 || search.Total != 1 {
		t.Fatalf("specific search cannot recover from list budget: %+v %v", search, err)
	}
	entries, err := readSearchDirectory(context.Background(), root, 2)
	if err != nil || len(entries) != 3 {
		t.Fatalf("bounded search allocation=%d err=%v", len(entries), err)
	}
}
