package executor

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sync/atomic"
	"time"
)

const WPPanelAccessSocketPath = "/run/ols-wpanel-wp-access/broker.sock"

type WPPanelAccessGrant struct {
	AdministratorID    int    `json:"administrator_id"`
	AdministratorLogin string `json:"administrator_login"`
	AdministratorProof string `json:"administrator_proof"`
	Domain             string `json:"domain"`
	InstallationPath   string `json:"installation_path"`
	Generation         string `json:"generation"`
}

type WPPanelAccessRedeemer func(context.Context, string, int, int, string) (WPPanelAccessGrant, error)
type wpPanelAccessPeerUIDKey struct{}

var wpPanelAccessBrokerReady atomic.Bool

func WPPanelAccessBrokerAvailable() bool { return wpPanelAccessBrokerReady.Load() }

func wpPanelAccessBrokerHandler(redeem WPPanelAccessRedeemer) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json")
		uid, ok := r.Context().Value(wpPanelAccessPeerUIDKey{}).(int)
		if r.Method != http.MethodPost || r.URL.Path != "/redeem" || r.URL.RawQuery != "" || !ok || uid <= 0 || redeem == nil {
			http.Error(w, `{"success":false}`, http.StatusForbidden)
			return
		}
		var req struct {
			Token      string `json:"token"`
			SiteID     int    `json:"site_id"`
			Generation string `json:"generation"`
		}
		r.Body = http.MaxBytesReader(w, r.Body, 2048)
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&req); err != nil || len(req.Token) != 43 || len(req.Generation) != 32 || req.SiteID <= 0 {
			http.Error(w, `{"success":false}`, http.StatusForbidden)
			return
		}
		if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
			http.Error(w, `{"success":false}`, http.StatusForbidden)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		grant, err := redeem(ctx, req.Token, req.SiteID, uid, req.Generation)
		if err != nil {
			http.Error(w, `{"success":false}`, http.StatusForbidden)
			return
		}
		_ = json.NewEncoder(w).Encode(struct {
			Success bool               `json:"success"`
			Data    WPPanelAccessGrant `json:"data"`
		}{true, grant})
	})
}
