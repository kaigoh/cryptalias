package cryptalias

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

func TestDomainVerifierHealthy(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	cfg := testConfig(t)
	cfg.Domains[0].Domain = "example.com"
	cfg.Domains[0].PublicKey = PublicKey(pub)
	cfg.Domains[0].PrivateKey = PrivateKey(priv)

	dir := t.TempDir()
	path := filepath.Join(dir, "config.yml")
	store := NewConfigStore(path, cfg)
	statuses := NewDomainStatusStore(cfg)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/cryptalias/configuration":
			WellKnownHandler(store).ServeHTTP(w, r)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	cfg.BaseURL = server.URL
	if err := store.Set(cfg); err != nil {
		t.Fatalf("apply config: %v", err)
	}

	origLookupIP := lookupIP
	origLookupTXT := lookupTXT
	lookupIP = func(string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("127.0.0.1")}, nil
	}
	lookupTXT = func(string) ([]string, error) {
		return []string{cfg.Domains[0].DNSTXTValue()}, nil
	}
	t.Cleanup(func() {
		lookupIP = origLookupIP
		lookupTXT = origLookupTXT
	})

	verifier := newDomainVerifier(store, statuses, 0)
	status := verifier.verifyDomain(context.Background(), cfg, cfg.Domains[0])
	if !status.Healthy {
		t.Fatalf("expected healthy domain, got unhealthy: %s", status.Message)
	}
	if !status.WellKnownOK || !status.DNSResolves || !status.DNSTXTOK {
		t.Fatalf("expected all checks to pass: %+v", status)
	}
}

func TestAliasResolverHandlerGatesUnhealthyDomain(t *testing.T) {
	store, _ := newTestStore(t)
	statuses := NewDomainStatusStore(store.Get())
	statuses.Update(DomainStatus{
		Domain:  "127.0.0.1",
		Healthy: false,
		Message: "dns txt mismatch",
	})

	resolver := &gateTestResolver{}
	req := httptest.NewRequest(http.MethodGet, "/_cryptalias/resolve/xmr/demo$127.0.0.1", nil)
	req.SetPathValue("ticker", "xmr")
	req.SetPathValue("alias", "demo$127.0.0.1")
	rr := httptest.NewRecorder()

	AliasResolverHandler(store, resolver, statuses).ServeHTTP(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d: %s", rr.Code, rr.Body.String())
	}
	if resolver.called {
		t.Fatalf("expected resolver not to be called when domain is unhealthy")
	}
}

func TestCheckDNSTXTAcceptsBase64URLWithoutPrefix(t *testing.T) {
	store, _ := newTestStore(t)
	domain := store.Get().Domains[0]

	origLookupTXT := lookupTXT
	lookupTXT = func(string) ([]string, error) {
		return []string{base64.RawURLEncoding.EncodeToString(domain.PublicKey)}, nil
	}
	t.Cleanup(func() { lookupTXT = origLookupTXT })

	if err := checkDNSTXT(domain); err != nil {
		t.Fatalf("expected dns txt check to pass, got: %v", err)
	}
}

type gateTestResolver struct {
	called bool
}

func (r *gateTestResolver) Resolve(context.Context, *Config, dynamicAliasInput) (WalletAddress, error) {
	r.called = true
	return WalletAddress{}, nil
}
