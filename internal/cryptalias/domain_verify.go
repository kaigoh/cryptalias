package cryptalias

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

const defaultDomainVerifyInterval = 5 * time.Minute

var (
	lookupIP  = net.LookupIP
	lookupTXT = net.LookupTXT
)

type domainVerifier struct {
	store    *ConfigStore
	statuses *DomainStatusStore
	client   *http.Client
	interval time.Duration
}

func newDomainVerifier(store *ConfigStore, statuses *DomainStatusStore, interval time.Duration) *domainVerifier {
	if interval <= 0 {
		interval = defaultDomainVerifyInterval
	}
	return &domainVerifier{
		store:    store,
		statuses: statuses,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
		interval: interval,
	}
}

func (v *domainVerifier) Start(ctx context.Context) {
	if v == nil || v.store == nil || v.statuses == nil {
		return
	}

	runOnce := func() {
		cfg := v.store.Get()
		v.statuses.Reconcile(cfg)
		for _, domainCfg := range cfg.Domains {
			status := v.verifyDomain(ctx, cfg, domainCfg)
			v.statuses.Update(status)
			if status.Healthy {
				slog.Info("domain verification ok", "domain", status.Domain)
				continue
			}
			slog.Error("domain verification failed", "domain", status.Domain, "message", status.Message)
		}
	}

	// Run immediately so we do not wait for the first interval.
	runOnce()

	ticker := time.NewTicker(v.interval)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				runOnce()
			}
		}
	}()
}

func (v *domainVerifier) verifyDomain(ctx context.Context, cfg *Config, domainCfg AliasDomainConfig) DomainStatus {
	status := DomainStatus{
		Domain:      strings.ToLower(domainCfg.Domain),
		Healthy:     true,
		LastChecked: time.Now().UTC(),
	}

	base, err := url.Parse(cfg.BaseURL)
	if err != nil || base.Host == "" {
		status.Healthy = false
		status.Message = "invalid base_url; cannot verify domain"
		return status
	}

	if err := v.checkWellKnown(ctx, base, domainCfg); err != nil {
		status.Healthy = false
		status.Message = fmt.Sprintf("well-known check failed: %v", err)
		return status
	}
	status.WellKnownOK = true

	if err := v.checkJWKS(ctx, base, domainCfg); err != nil {
		status.Healthy = false
		status.Message = fmt.Sprintf("jwks check failed: %v", err)
		return status
	}
	status.JWKSOK = true

	if !shouldCheckDNS(domainCfg.Domain) {
		status.DNSResolves = true
		status.DNSTXTOK = true
		status.Message = "dns checks skipped for local domain"
		return status
	}

	if err := checkDNSResolution(domainCfg.Domain); err != nil {
		status.Healthy = false
		status.Message = fmt.Sprintf("dns resolution failed: %v", err)
		return status
	}
	status.DNSResolves = true

	if err := checkDNSTXT(domainCfg); err != nil {
		status.Healthy = false
		status.Message = fmt.Sprintf("dns txt check failed: %v", err)
		return status
	}
	status.DNSTXTOK = true

	status.Message = "ok"
	return status
}

func (v *domainVerifier) checkWellKnown(ctx context.Context, base *url.URL, domainCfg AliasDomainConfig) error {
	body, err := v.getWithHost(ctx, base, "/.well-known/cryptalias", domainCfg.Domain)
	if err != nil {
		return err
	}

	var raw struct {
		Domain string          `json:"domain"`
		Key    json.RawMessage `json:"key"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	if !strings.EqualFold(strings.TrimSpace(raw.Domain), domainCfg.Domain) {
		return fmt.Errorf("domain mismatch: got %q", raw.Domain)
	}

	key, err := jwk.ParseKey(raw.Key)
	if err != nil {
		return fmt.Errorf("parse key: %w", err)
	}
	return ensureKeyMatchesDomain(key, domainCfg)
}

func (v *domainVerifier) checkJWKS(ctx context.Context, base *url.URL, domainCfg AliasDomainConfig) error {
	body, err := v.getWithHost(ctx, base, "/_cryptalias/keys", domainCfg.Domain)
	if err != nil {
		return err
	}

	var raw struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	if len(raw.Keys) == 0 {
		return errors.New("no keys returned")
	}

	for _, item := range raw.Keys {
		key, err := jwk.ParseKey(item)
		if err != nil {
			continue
		}
		kid, ok := key.KeyID()
		if !ok || !strings.EqualFold(kid, domainCfg.Domain) {
			continue
		}
		return ensureKeyMatchesDomain(key, domainCfg)
	}
	return fmt.Errorf("no jwks key found for domain %s", domainCfg.Domain)
}

func (v *domainVerifier) getWithHost(ctx context.Context, base *url.URL, path, host string) ([]byte, error) {
	endpoint := *base
	endpoint.Path = path
	endpoint.RawQuery = ""
	endpoint.Fragment = ""

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return nil, err
	}
	// Use base_url for transport but verify per-domain responses via Host.
	req.Host = host
	req.Header.Set("Accept", "application/json")

	resp, err := v.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return io.ReadAll(resp.Body)
}

func ensureKeyMatchesDomain(key jwk.Key, domainCfg AliasDomainConfig) error {
	kid, ok := key.KeyID()
	if !ok || !strings.EqualFold(kid, domainCfg.Domain) {
		return fmt.Errorf("kid mismatch: got %v", kid)
	}

	var pub ed25519.PublicKey
	if err := jwk.Export(key, &pub); err != nil {
		return fmt.Errorf("export public key: %w", err)
	}
	if !bytesEqual([]byte(pub), []byte(domainCfg.PublicKey)) {
		return errors.New("public key mismatch")
	}
	return nil
}

func shouldCheckDNS(domain string) bool {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return false
	}
	if net.ParseIP(domain) != nil {
		return false
	}
	if domain == "localhost" || strings.HasSuffix(domain, ".localhost") {
		return false
	}
	return true
}

func checkDNSResolution(domain string) error {
	ips, err := lookupIP(domain)
	if err != nil {
		return err
	}
	if len(ips) == 0 {
		return errors.New("no A/AAAA records")
	}
	return nil
}

func checkDNSTXT(domainCfg AliasDomainConfig) error {
	records, err := lookupTXT("_cryptalias." + domainCfg.Domain)
	if err != nil {
		return err
	}
	if len(records) == 0 {
		return errors.New("no TXT records found")
	}
	expected := domainCfg.DNSTXTValue()
	for _, record := range records {
		if strings.TrimSpace(record) == expected {
			return nil
		}
	}
	return fmt.Errorf("expected %q, got %q", expected, strings.Join(records, ", "))
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// DNSTXTValueFromKey is used by tests and status output to render the expected
// TXT value from a raw public key.
func DNSTXTValueFromKey(pub []byte) string {
	return "pubkey=" + base64.StdEncoding.EncodeToString(pub)
}
