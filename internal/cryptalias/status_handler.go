package cryptalias

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"
)

type domainStatusResponse struct {
	Version   uint         `json:"version"`
	CheckedAt time.Time    `json:"checked_at"`
	Healthy   bool         `json:"healthy"`
	Domain    DomainStatus `json:"domain"`
}

// WellKnownStatusHandler exposes verifier state for the resolved domain only.
func WellKnownStatusHandler(store *ConfigStore, statuses *DomainStatusStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := store.Get()
		if statuses != nil {
			statuses.Reconcile(cfg)
		}
		domain, err := cfg.GetDomain(r.Host)
		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("404 page not found"))
			return
		}
		status := DomainStatus{Domain: domain.Domain, Healthy: true, Message: "domain not tracked", LastChecked: time.Now().UTC()}
		if statuses != nil {
			if s, ok := statuses.Get(domain.Domain); ok {
				status = s
			}
		}
		if status.LastChecked.IsZero() {
			status = DomainStatus{
				Domain:      domain.Domain,
				Healthy:     true,
				LastChecked: time.Now().UTC(),
			}
		}
		checkedAt := status.LastChecked
		resp := domainStatusResponse{Version: VERSION, CheckedAt: checkedAt, Healthy: status.Healthy, Domain: status}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			slog.Error("status encode failed", "error", err)
		}
	}
}
