package cryptalias

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
)

func WellKnownHandler(store *ConfigStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		slog.Debug("well-known request", "host", r.Host, "path", r.URL.Path)
		c := store.Get()

		// Is this a domain we're configured to resolve?
		domain, err := c.GetDomain(r.Host)
		if err != nil {
			slog.Warn("well-known domain not configured", "host", r.Host)
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprintf(w, "404 page not found")
			return
		}

		key, err := domain.GetJWK()
		if err != nil {
			slog.Error("well-known jwk generation failed", "domain", domain.Domain, "error", err)
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, err.Error())
			return
		}

		d := WalletDomain{
			Version:      VERSION,
			Domain:       domain.Domain,
			PublicKey:    key,
			ResolverMode: AliasResolverModeDelegated,
			Resolver:     AliasResolver{ResolverEndpoint: c.BaseURL},
		}

		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(d)
		slog.Debug("well-known response sent", "domain", domain.Domain)

	}
}

// WellKnownKeysHandler serves the single domain key on the resolved domain.
func WellKnownKeysHandler(store *ConfigStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		slog.Debug("well-known keys request", "host", r.Host, "path", r.URL.Path)
		c := store.Get()

		domain, err := c.GetDomain(r.Host)
		if err != nil {
			slog.Warn("well-known keys domain not configured", "host", r.Host)
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprintf(w, "404 page not found")
			return
		}

		key, err := domain.GetJWK()
		if err != nil {
			slog.Error("well-known keys jwk generation failed", "domain", domain.Domain, "error", err)
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, err.Error())
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(struct {
			Domain string  `json:"domain"`
			Key    jwk.Key `json:"key"`
		}{
			Domain: domain.Domain,
			Key:    key,
		})
		slog.Debug("well-known keys response sent", "domain", domain.Domain)
	}
}

func AliasResolverHandler(store *ConfigStore, resolver walletResolver, statuses *DomainStatusStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ticker := r.PathValue("ticker")
		rawAlias := r.PathValue("alias")
		slog.Debug("resolve request", "ticker", ticker, "alias", rawAlias)

		if len(strings.TrimSpace(ticker)) == 0 || len(strings.TrimSpace(rawAlias)) == 0 {
			slog.Warn("resolve rejected empty input")
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, "400 ticker and alias must not be empty")
			return
		}

		c := store.Get()
		if statuses != nil {
			statuses.Reconcile(c)
		}
		if statuses != nil {
			if domain, err := ParseAliasDomain(rawAlias); err == nil {
				if healthy, status := statuses.Healthy(domain); !healthy {
					slog.Warn("resolve gated unhealthy domain", "domain", domain, "message", status.Message)
					w.WriteHeader(http.StatusServiceUnavailable)
					fmt.Fprintf(w, "503 domain unhealthy: %s", status.Message)
					return
				}
			}
		}
		identity := newClientIdentity(c.Resolution.ClientIdentity)
		clientKey := identity.Key(r)
		// Propagate the derived client identity so the resolver cache can bind to it.
		ctx := withClientKey(r.Context(), clientKey)

		alias, err := ResolveAlias(ctx, rawAlias, ticker, c, resolver)
		if err != nil {
			if errors.Is(err, ErrAliasNotFound) {
				slog.Warn("resolve alias not found", "ticker", ticker, "alias", rawAlias, "client", clientKey)
				w.WriteHeader(http.StatusNotFound)
				fmt.Fprintf(w, "404 %s", ErrAliasNotFound.Error())
				return
			}
			slog.Error("resolve failed", "ticker", ticker, "alias", rawAlias, "client", clientKey, "error", err)
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, "500 %s", err.Error())
			return
		}

		// Prepare the response...
		nonce, err := NewNonce()
		if err != nil {
			slog.Error("resolve nonce generation failed", "error", err)
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, "500 %s", err.Error())
			return
		}
		o := ResolvedAddress{
			Version: VERSION,
			Ticker:  alias.Wallet.Ticker,
			Address: alias.Wallet.Address,
			Expires: time.Now().UTC().Add(60 * time.Second),
			Nonce:   nonce,
		}
		j, err := json.Marshal(o)
		if err != nil {
			slog.Error("resolve marshal failed", "error", err)
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, "500 %s", err.Error())
			return
		}

		// ...and sign it
		signed, err := jws.Sign(j, jws.WithKey(jwa.EdDSA(), alias.SigningKey))
		if err != nil {
			slog.Error("resolve signing failed", "error", err)
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, "500 %s", err.Error())
			return
		}

		// ...and send it
		// The response body is a compact JWS, not plain JSON.
		w.Header().Set("Content-Type", "application/jose")
		w.WriteHeader(http.StatusOK)
		w.Write(signed)
		slog.Debug("resolve response sent", "ticker", alias.Wallet.Ticker, "domain", alias.Domain)
	}
}
