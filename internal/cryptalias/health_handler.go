package cryptalias

import (
	"encoding/json"
	"net/http"
	"time"
)

type healthResponse struct {
	Status           string    `json:"status"`
	Version          uint      `json:"version"`
	Time             time.Time `json:"time"`
	OverallOK        bool      `json:"overall_ok"`
	UnhealthyDomains int       `json:"unhealthy_domains"`
}

// HealthHandler is a liveness endpoint intended for container health checks.
// It always returns 200 when the process is up, and reports domain health in the body.
func HealthHandler(statuses *DomainStatusStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		unhealthy := 0
		overall := true
		if statuses != nil {
			for _, status := range statuses.List() {
				if status.Healthy {
					continue
				}
				unhealthy++
				overall = false
			}
		}

		resp := healthResponse{
			Status:           "ok",
			Version:          VERSION,
			Time:             time.Now().UTC(),
			OverallOK:        overall,
			UnhealthyDomains: unhealthy,
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(resp)
	}
}
