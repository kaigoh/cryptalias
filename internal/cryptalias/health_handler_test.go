package cryptalias

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHealthHandlerReportsDomainHealth(t *testing.T) {
	cfg := testConfig(t)
	statuses := NewDomainStatusStore(cfg)
	statuses.Update(DomainStatus{Domain: "127.0.0.1", Healthy: false, Message: "dns txt mismatch"})

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rr := httptest.NewRecorder()

	HealthHandler(statuses).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var resp healthResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if resp.OverallOK {
		t.Fatalf("expected overall_ok=false when a domain is unhealthy")
	}
	if resp.UnhealthyDomains != 1 {
		t.Fatalf("expected unhealthy_domains=1, got %d", resp.UnhealthyDomains)
	}
}
