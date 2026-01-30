package cryptalias

import (
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jws"
)

func newTestStore(t *testing.T) (*ConfigStore, *WalletResolver) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yml")
	store := NewConfigStore(path, testConfig(t))
	resolver, err := NewWalletResolver(path)
	if err != nil {
		t.Fatalf("new wallet resolver: %v", err)
	}
	return store, resolver
}

func TestWellKnownHandler(t *testing.T) {
	store, _ := newTestStore(t)
	req := httptest.NewRequest(http.MethodGet, "/.well-known/cryptalias/configuration", nil)
	req.Host = "127.0.0.1"
	rr := httptest.NewRecorder()

	WellKnownHandler(store).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("expected application/json content-type, got %q", ct)
	}
}

func TestWellKnownStatusHandler(t *testing.T) {
	store, _ := newTestStore(t)
	statuses := NewDomainStatusStore(store.Get())
	statuses.Update(DomainStatus{
		Domain:      "127.0.0.1",
		Healthy:     false,
		Message:     "dns txt mismatch",
		LastChecked: time.Now().UTC(),
	})
	req := httptest.NewRequest(http.MethodGet, "/.well-known/cryptalias/status", nil)
	req.Host = "127.0.0.1"
	rr := httptest.NewRecorder()

	WellKnownStatusHandler(store, statuses).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var body struct {
		Healthy bool         `json:"healthy"`
		Domain  DomainStatus `json:"domain"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Healthy || body.Domain.Domain != "127.0.0.1" {
		t.Fatalf("unexpected body: %+v", body)
	}
}

func TestAliasResolverHandlerSignsPayload(t *testing.T) {
	store, resolver := newTestStore(t)
	statuses := NewDomainStatusStore(store.Get())
	req := httptest.NewRequest(http.MethodGet, "/_cryptalias/resolve/xmr/demo$127.0.0.1", nil)
	req.SetPathValue("ticker", "xmr")
	req.SetPathValue("alias", "demo$127.0.0.1")
	rr := httptest.NewRecorder()

	AliasResolverHandler(store, resolver, statuses).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/jose" {
		t.Fatalf("expected application/jose content-type, got %q", ct)
	}

	cfg := store.Get()
	pubKey := ed25519.PublicKey(cfg.Domains[0].PublicKey)
	verified, err := jws.Verify(rr.Body.Bytes(), jws.WithKey(jwa.EdDSA(), pubKey))
	if err != nil {
		t.Fatalf("verify jws: %v", err)
	}

	var payload ResolvedAddress
	if err := json.Unmarshal(verified, &payload); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if payload.Ticker != "xmr" {
		t.Fatalf("expected ticker xmr, got %q", payload.Ticker)
	}
	if payload.Address != "addr-root" {
		t.Fatalf("expected address addr-root, got %q", payload.Address)
	}
	if payload.Nonce == "" {
		t.Fatalf("expected nonce to be set")
	}
	if !payload.Expires.After(time.Now().UTC().Add(30 * time.Second)) {
		t.Fatalf("expected expires to be in the future, got %v", payload.Expires)
	}
}

func TestAliasResolverHandlerAcceptsPrefixedAlias(t *testing.T) {
	store, resolver := newTestStore(t)
	statuses := NewDomainStatusStore(store.Get())
	req := httptest.NewRequest(http.MethodGet, "/_cryptalias/resolve/xmr:demo$127.0.0.1", nil)
	req.SetPathValue("alias", "xmr:demo$127.0.0.1")
	rr := httptest.NewRecorder()

	AliasResolverHandler(store, resolver, statuses).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/jose" {
		t.Fatalf("expected application/jose content-type, got %q", ct)
	}

	cfg := store.Get()
	pubKey := ed25519.PublicKey(cfg.Domains[0].PublicKey)
	verified, err := jws.Verify(rr.Body.Bytes(), jws.WithKey(jwa.EdDSA(), pubKey))
	if err != nil {
		t.Fatalf("verify jws: %v", err)
	}

	var payload ResolvedAddress
	if err := json.Unmarshal(verified, &payload); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if payload.Ticker != "xmr" {
		t.Fatalf("expected ticker xmr, got %q", payload.Ticker)
	}
	if payload.Address != "addr-root" {
		t.Fatalf("expected address addr-root, got %q", payload.Address)
	}
}
