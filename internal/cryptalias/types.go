package cryptalias

import (
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

type AliasResolver struct {
	ResolverEndpoint string `json:"resolver_endpoint"`
	KeysEndpoint     string `json:"keys_endpoint,omitempty"`
}

type AliasResolverMode string

const (
	AliasResolverModeDelegated AliasResolverMode = "delegated"
	AliasResolverModeStatic    AliasResolverMode = "static"
)

type WalletAlias struct {
	Alias   string `json:"alias" yaml:"alias"`
	Ticker  string `json:"ticker" yaml:"ticker"`
	Address string `json:"address" yaml:"address,omitempty"`
}

type WalletDomain struct {
	Version      uint              `json:"version"`
	ResolverMode AliasResolverMode `json:"resolver_mode"`
	Resolver     AliasResolver     `json:"resolver"`
	Domain       string            `json:"domain"`
	PublicKey    jwk.Key           `json:"key"`
	Aliases      []WalletAlias     `json:"aliases,omitempty"`
}

type WalletDomainsKeys struct {
	Keys []jwk.Key `json:"keys"`
}

type ResolvedAddress struct {
	Version uint      `json:"version"`
	Ticker  string    `json:"ticker"`
	Address string    `json:"address"`
	Expires time.Time `json:"expires"`
	Nonce   string    `json:"string"`
}
