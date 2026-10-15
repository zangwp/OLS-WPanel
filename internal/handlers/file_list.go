package handlers

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"sort"
	"time"
)

const fileListEntryLimit = 20000
const fileListReadBatch = 256
const fileListTimeout = 5 * time.Second

var errFileListTooLarge = errors.New("directory listing exceeds entry budget")
var errFileListChanged = errors.New("directory entry metadata unavailable")

type fileListOptions struct {
	page, perPage   int
	sortBy, sortDir string
	paged           bool
	entryLimit      int
}

type fileListPage struct {
	files                            []fileEntry
	total, page, perPage, totalPages int
}

// readFileList never returns a successful partial directory. Name/type order
// needs only entry names and type hints; metadata is read for the selected page.
// Size/time sorting still reads every entry's metadata within the same budget.
func readFileList(ctx context.Context, dir fs.ReadDirFile, options fileListOptions) (fileListPage, error) {
	var result fileListPage
	limit := options.entryLimit
	if limit <= 0 {
		limit = fileListEntryLimit
	}
	files := make([]fileEntry, 0)
	entries := make(map[string]fs.DirEntry)
	needsAllMetadata := !options.paged || options.sortBy == "size" || options.sortBy == "time"
	for {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		batch, err := dir.ReadDir(fileListReadBatch)
		if err != nil && !errors.Is(err, io.EOF) {
			return result, err
		}
		if len(files)+len(batch) > limit {
			return result, errFileListTooLarge
		}
		for _, entry := range batch {
			if err := ctx.Err(); err != nil {
				return result, err
			}
			if _, exists := entries[entry.Name()]; exists {
				return result, errFileListChanged
			}
			entries[entry.Name()] = entry
			item := fileEntry{Name: entry.Name(), IsDir: entry.IsDir()}
			if needsAllMetadata {
				if err := fillFileListMetadata(&item, entry); err != nil {
					return result, err
				}
			}
			files = append(files, item)
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if len(batch) == 0 {
			return result, errFileListChanged
		}
	}
	// os.ReadDir previously supplied lexical name order before the stable sort.
	// Preserve its tie order (including names differing only by case) even though
	// the bounded ReadDir batches arrive in filesystem order.
	sort.Slice(files, func(i, j int) bool { return files[i].Name < files[j].Name })
	sortFileEntries(files, options.sortBy, options.sortDir)
	result.total = len(files)
	result.page, result.perPage = normalizeFilePage(options.page, options.perPage)
	result.totalPages = 1
	result.files = files
	if options.paged {
		result.files, result.page, result.totalPages = paginateFileEntries(files, result.page, result.perPage)
	} else if len(files) > 0 {
		result.perPage = len(files)
	}
	if !needsAllMetadata {
		for i := range result.files {
			if err := ctx.Err(); err != nil {
				return fileListPage{}, err
			}
			if err := fillFileListMetadata(&result.files[i], entries[result.files[i].Name]); err != nil {
				return fileListPage{}, err
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return fileListPage{}, err
	}
	return result, nil
}

func fillFileListMetadata(item *fileEntry, entry fs.DirEntry) error {
	info, err := entry.Info()
	if err != nil {
		return fmt.Errorf("%w: %v", errFileListChanged, err)
	}
	item.Size = info.Size()
	item.Mode = info.Mode().String()
	item.ModTime = info.ModTime().Format("2006-01-02 15:04:05")
	return nil
}
