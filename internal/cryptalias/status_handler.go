package cryptalias

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"
)

type statusResponse struct {
	Version      uint           `json:"version"`
	CheckedAt    time.Time      `json:"checked_at"`
	OverallOK    bool           `json:"overall_ok"`
	DomainStatus []DomainStatus `json:"domains"`
}

// StatusHandler exposes the verifier state so operators and clients can see
// when a domain has been gated due to misconfiguration.
func StatusHandler(statuses *DomainStatusStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		list := statuses.List()
		overall := true
		checkedAt := time.Time{}
		for _, status := range list {
			if !status.Healthy {
				overall = false
			}
			if status.LastChecked.After(checkedAt) {
				checkedAt = status.LastChecked
			}
		}
		if checkedAt.IsZero() {
			checkedAt = time.Now().UTC()
		}

		resp := statusResponse{
			Version:      VERSION,
			CheckedAt:    checkedAt,
			OverallOK:    overall,
			DomainStatus: list,
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			slog.Error("status encode failed", "error", err)
		}
	}
}
