package handlers

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/zangwp/OLS-WPanel/internal/executor"
	"github.com/zangwp/OLS-WPanel/internal/models"
)

type siteBackupExportResponseFixture struct {
	body   string
	fail   bool
	closed *int
}

func (f *siteBackupExportResponseFixture) Filename() string { return "example.com_complete.tar" }
func (f *siteBackupExportResponseFixture) Size() int64      { return int64(len(f.body)) }
func (f *siteBackupExportResponseFixture) Close() error     { *f.closed++; return nil }
func (f *siteBackupExportResponseFixture) Write(ctx context.Context, w io.Writer) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if f.fail {
		_, err := io.WriteString(w, f.body[:2])
		if err != nil {
			return err
		}
		return errors.New("fixture disconnected")
	}
	_, err := io.WriteString(w, f.body)
	return err
}

func TestSiteBackupBundleDownloadBindsSiteAndStreamsWithoutJSONFooter(t *testing.T) {
	for _, outcome := range []string{"success", "unavailable", "interrupted", "wrong_site", "invalid_id"} {
		t.Run(outcome, func(t *testing.T) {
			router := setupSiteBackupHandlerFixture(t)
			old := prepareSiteBackupExport
			t.Cleanup(func() { prepareSiteBackupExport = old })
			calls, closed := 0, 0
			prepareSiteBackupExport = func(ctx context.Context, site *models.Website, id string) (executor.SiteBackupExport, error) {
				calls++
				if site.ID != 1 || id != testSiteBackupID {
					t.Fatal("unbound export request", site, id)
				}
				if outcome == "unavailable" {
					return nil, errors.New("backup hash changed")
				}
				return &siteBackupExportResponseFixture{body: "TAR-FIXTURE", fail: outcome == "interrupted", closed: &closed}, nil
			}
			url := "/api/websites/1/site-backups/" + testSiteBackupID + "/download?component=bundle"
			if outcome == "wrong_site" {
				url = strings.Replace(url, "websites/1/", "websites/999/", 1)
			}
			if outcome == "invalid_id" {
				url = strings.Replace(url, testSiteBackupID, "invalid", 1)
			}
			rec := siteBackupRequest(router, http.MethodGet, url, "")
			if outcome == "wrong_site" || outcome == "invalid_id" {
				if calls != 0 || rec.Code == http.StatusOK {
					t.Fatal("invalid binding reached export", rec.Code, calls)
				}
				return
			}
			if outcome == "unavailable" {
				if rec.Code != http.StatusConflict || rec.Header().Get("Content-Disposition") != "" {
					t.Fatal("failed preparation advertised an archive", rec.Code, rec.Header())
				}
				return
			}
			if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "application/x-tar" || rec.Header().Get("Content-Length") != "11" || rec.Header().Get("Cache-Control") != "private, no-store" || closed != 1 {
				t.Fatal("export headers or cleanup invalid", rec.Code, rec.Header(), closed)
			}
			if outcome == "interrupted" {
				if rec.Body.String() != "TA" {
					t.Fatal("partial archive gained JSON or success footer", rec.Body.String())
				}
			} else if rec.Body.String() != "TAR-FIXTURE" {
				t.Fatal(rec.Body.String())
			}
		})
	}
}
