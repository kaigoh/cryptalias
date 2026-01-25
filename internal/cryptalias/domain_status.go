package cryptalias

import (
	"sort"
	"strings"
	"sync"
	"time"
)

// DomainStatus captures the health of a configured domain as observed by the
// periodic verifier. When Healthy is false, resolution is gated for that domain.
type DomainStatus struct {
	Domain      string    `json:"domain"`
	Healthy     bool      `json:"healthy"`
	Message     string    `json:"message,omitempty"`
	LastChecked time.Time `json:"last_checked"`

	WellKnownOK bool `json:"well_known_ok"`
	JWKSOK      bool `json:"jwks_ok"`
	DNSResolves bool `json:"dns_resolves"`
	DNSTXTOK    bool `json:"dns_txt_ok"`
}

// DomainStatusStore holds domain health state separate from config so the
// verifier and request handlers can coordinate safely.
type DomainStatusStore struct {
	mu       sync.RWMutex
	statuses map[string]DomainStatus
}

func NewDomainStatusStore(cfg *Config) *DomainStatusStore {
	s := &DomainStatusStore{statuses: make(map[string]DomainStatus)}
	s.Reconcile(cfg)
	return s
}

// Reconcile ensures the store tracks the current set of configured domains.
func (s *DomainStatusStore) Reconcile(cfg *Config) {
	if cfg == nil {
		return
	}
	domains := make(map[string]struct{}, len(cfg.Domains))
	for _, d := range cfg.Domains {
		domain := strings.ToLower(strings.TrimSpace(d.Domain))
		if domain == "" {
			continue
		}
		domains[domain] = struct{}{}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	for domain := range s.statuses {
		if _, ok := domains[domain]; !ok {
			delete(s.statuses, domain)
		}
	}
	for domain := range domains {
		if _, ok := s.statuses[domain]; ok {
			continue
		}
		s.statuses[domain] = DomainStatus{
			Domain:  domain,
			Healthy: true,
			Message: "not yet verified",
		}
	}
}

func (s *DomainStatusStore) Update(status DomainStatus) {
	domain := strings.ToLower(strings.TrimSpace(status.Domain))
	if domain == "" {
		return
	}
	status.Domain = domain
	if status.LastChecked.IsZero() {
		status.LastChecked = time.Now().UTC()
	}

	s.mu.Lock()
	s.statuses[domain] = status
	s.mu.Unlock()
}

func (s *DomainStatusStore) Get(domain string) (DomainStatus, bool) {
	domain = strings.ToLower(strings.TrimSpace(domain))
	s.mu.RLock()
	status, ok := s.statuses[domain]
	s.mu.RUnlock()
	return status, ok
}

func (s *DomainStatusStore) Healthy(domain string) (bool, DomainStatus) {
	status, ok := s.Get(domain)
	if !ok {
		return true, DomainStatus{Domain: strings.ToLower(strings.TrimSpace(domain)), Healthy: true, Message: "domain not tracked"}
	}
	return status.Healthy, status
}

// List returns a sorted snapshot so callers can render status pages safely.
func (s *DomainStatusStore) List() []DomainStatus {
	s.mu.RLock()
	out := make([]DomainStatus, 0, len(s.statuses))
	for _, status := range s.statuses {
		out = append(out, status)
	}
	s.mu.RUnlock()

	sort.Slice(out, func(i, j int) bool {
		return out[i].Domain < out[j].Domain
	})
	return out
}
