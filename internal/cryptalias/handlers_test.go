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
	"github.com/lestrrat-go/jwx/v3/jwk"
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
	req := httptest.NewRequest(http.MethodGet, "/.well-known/cryptalias", nil)
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

func TestJWKSKeysHandler(t *testing.T) {
	store, _ := newTestStore(t)
	req := httptest.NewRequest(http.MethodGet, "/_cryptalias/keys", nil)
	rr := httptest.NewRecorder()

	JWKSKeysHandler(store).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	set, err := jwk.Parse(rr.Body.Bytes())
	if err != nil {
		t.Fatalf("parse jwk set: %v", err)
	}
	if set.Len() != 1 {
		t.Fatalf("expected 1 key, got %d", set.Len())
	}
	key, ok := set.Key(0)
	if !ok {
		t.Fatalf("expected key at index 0")
	}
	kid, ok := key.KeyID()
	if !ok || kid != "127.0.0.1" {
		t.Fatalf("expected kid 127.0.0.1, got %q (ok=%v)", kid, ok)
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
