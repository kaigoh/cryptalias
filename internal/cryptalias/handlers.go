package cryptalias

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

func WellKnownHandler(store *ConfigStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c := store.Get()

		// Is this a domain we're configured to resolve?
		domain, err := c.GetDomain(r.Host)
		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprintf(w, "404 page not found")
			return
		}

		key, err := domain.GetJWK()
		if err != nil {
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

	}
}

func JWKSKeysHandler(store *ConfigStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c := store.Get()
		keys := make([]jwk.Key, 0, len(c.Domains))

		for _, d := range c.Domains {
			key, err := d.GetJWK()
			if err != nil {
				continue
			}
			keys = append(keys, key)
		}

		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(WalletDomainsKeys{Keys: keys})

	}
}
