package cryptalias

import (
	"encoding/json"
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

func JWKSKeysHandler(store *ConfigStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		slog.Debug("jwks request", "path", r.URL.Path)
		c := store.Get()
		keys := make([]jwk.Key, 0, len(c.Domains))

		for _, d := range c.Domains {
			key, err := d.GetJWK()
			if err != nil {
				slog.Warn("jwks skipping domain", "domain", d.Domain, "error", err)
				continue
			}
			keys = append(keys, key)
		}

		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(WalletDomainsKeys{Keys: keys})
		slog.Debug("jwks response sent", "keys", len(keys))

	}
}

func AliasResolverHandler(store *ConfigStore) http.HandlerFunc {
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

		alias, err := ParseAlias(rawAlias, ticker, c)
		if err != nil {
			slog.Warn("resolve alias not found", "ticker", ticker, "alias", rawAlias, "error", err)
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprintf(w, "404 %s", err.Error())
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
		w.Header().Set("Content-Type", "application/jose")
		w.WriteHeader(http.StatusOK)
		w.Write(signed)
		slog.Debug("resolve response sent", "ticker", alias.Wallet.Ticker, "domain", alias.Domain)
	}
}
