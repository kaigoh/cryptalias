package cryptalias

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"gopkg.in/yaml.v2"
)

// Config is the full runtime configuration loaded from config.yml.
// It is treated as immutable once applied to the ConfigStore.
type Config struct {
	BaseURL    string              `yaml:"base_url"`
	PublicPort uint16              `yaml:"public_port"`
	Logging    LoggingConfig       `yaml:"logging,omitempty"`
	RateLimit  RateLimitConfig     `yaml:"rate_limit,omitempty"`
	Resolution ResolutionConfig    `yaml:"resolution,omitempty"`
	Domains    []AliasDomainConfig `yaml:"domains"`
	Tokens     []TokenConfig       `yaml:"tokens"`
}

func (c *Config) Clone() *Config {
	if c == nil {
		return nil
	}
	out := &Config{
		BaseURL:    c.BaseURL,
		PublicPort: c.PublicPort,
		Logging:    c.Logging,
		RateLimit:  c.RateLimit.Clone(),
		Resolution: c.Resolution.Clone(),
		Domains:    make([]AliasDomainConfig, len(c.Domains)),
		Tokens:     make([]TokenConfig, len(c.Tokens)),
	}
	for i := range c.Domains {
		out.Domains[i] = c.Domains[i].Clone()
	}
	for i := range c.Tokens {
		out.Tokens[i] = c.Tokens[i].Clone()
	}
	return out
}

// Normalize fills defaults, stabilizes casing/whitespace, and may persist
// generated keys back to disk so reloads remain deterministic.
func (c *Config) Normalize(path string) {
	c.BaseURL = strings.TrimSuffix(c.BaseURL, "/")
	if strings.TrimSpace(c.Logging.Level) == "" {
		c.Logging.Level = "info"
	} else {
		c.Logging.Level = strings.ToLower(strings.TrimSpace(c.Logging.Level))
	}
	if c.RateLimit.RequestsPerMinute <= 0 {
		c.RateLimit.RequestsPerMinute = 60
	}
	if c.RateLimit.Burst <= 0 {
		c.RateLimit.Burst = 10
	}
	if c.Resolution.TTLSeconds <= 0 {
		c.Resolution.TTLSeconds = 60
	}
	if c.Resolution.ClientIdentity.Strategy == "" {
		c.Resolution.ClientIdentity.Strategy = ClientIdentityStrategyXFF
	}
	if strings.TrimSpace(c.Resolution.ClientIdentity.Header) == "" {
		c.Resolution.ClientIdentity.Header = "X-Forwarded-For"
	}
	triggerSave := false
	// Normalize case for stable matching across requests.
	for i := range c.Domains {
		c.Domains[i].Domain = strings.ToLower(c.Domains[i].Domain)
		for a := range c.Domains[i].Aliases {
			c.Domains[i].Aliases[a].Alias = strings.ToLower(c.Domains[i].Aliases[a].Alias)
			c.Domains[i].Aliases[a].Wallet.Ticker = strings.ToLower(c.Domains[i].Aliases[a].Wallet.Ticker)
			normalizeWalletAddress(&c.Domains[i].Aliases[a].Wallet)
			for t := range c.Domains[i].Aliases[a].Tags {
				c.Domains[i].Aliases[a].Tags[t].Tag = strings.ToLower(c.Domains[i].Aliases[a].Tags[t].Tag)
				c.Domains[i].Aliases[a].Tags[t].Wallet.Ticker = strings.ToLower(c.Domains[i].Aliases[a].Tags[t].Wallet.Ticker)
				normalizeWalletAddress(&c.Domains[i].Aliases[a].Tags[t].Wallet)
			}
		}
		if result, err := c.Domains[i].GenerateKeys(); !result && err != nil {
			panic(err)
		} else if result {
			triggerSave = true
		}
	}
	if triggerSave {
		// Persist generated keys so subsequent reloads are deterministic.
		SaveConfig(path, c)
	}
}

// Validate checks that the normalized config is internally consistent.
func (c *Config) Validate() error {
	if c.BaseURL == "" {
		return fmt.Errorf("base_url is required")
	}
	if c.PublicPort == 0 {
		return fmt.Errorf("public_port must be set")
	}
	if _, ok := parseLogLevel(c.Logging.Level); !ok {
		return fmt.Errorf("logging.level must be one of: debug, info, warn, error")
	}
	if c.RateLimit.EnabledOrDefault() {
		if c.RateLimit.RequestsPerMinute <= 0 {
			return fmt.Errorf("rate_limit.requests_per_minute must be > 0")
		}
		if c.RateLimit.Burst <= 0 {
			return fmt.Errorf("rate_limit.burst must be > 0")
		}
	}
	if c.Resolution.TTLSeconds <= 0 {
		return fmt.Errorf("resolution.ttl_seconds must be > 0")
	}
	switch c.Resolution.ClientIdentity.Strategy {
	case ClientIdentityStrategyRemoteAddr, ClientIdentityStrategyXFF, ClientIdentityStrategyXFFUA, ClientIdentityStrategyHeader, ClientIdentityStrategyHeaderUA:
	default:
		return fmt.Errorf("resolution.client_identity.strategy must be one of: remote_addr, xff, xff_ua, header, header_ua")
	}
	if (c.Resolution.ClientIdentity.Strategy == ClientIdentityStrategyHeader || c.Resolution.ClientIdentity.Strategy == ClientIdentityStrategyHeaderUA) && strings.TrimSpace(c.Resolution.ClientIdentity.Header) == "" {
		return fmt.Errorf("resolution.client_identity.header is required when strategy is header or header_ua")
	}
	if len(c.Domains) == 0 {
		return fmt.Errorf("at least one domain is required")
	}
	for i, d := range c.Domains {
		if d.Domain == "" {
			return fmt.Errorf("domains[%d].domain is required", i)
		}
		if len(d.PrivateKey) == 0 || len(d.PublicKey) == 0 {
			return fmt.Errorf("domains[%d] keys are required", i)
		}
	}
	if len(c.Tokens) == 0 {
		return fmt.Errorf("at least one token (i.e. cryptocurrency / asset) is required")
	}
	for i, t := range c.Tokens {
		if len(t.Name) == 0 {
			return fmt.Errorf("tokens[%d].name is required", i)
		}
		if len(t.Tickers) == 0 {
			return fmt.Errorf("at least one tokens[%d].tickers is required, i.e. xmr, btc etc.", i)
		}
		if t.Endpoint.EndpointType == "" {
			return fmt.Errorf("tokens[%d].endpoint.type is required (internal or external)", i)
		}
		if t.Endpoint.EndpointAddress == "" {
			return fmt.Errorf("tokens[%d].endpoint.address is required", i)
		}
	}
	return nil
}

func (c *Config) GetDomain(domain string) (*AliasDomainConfig, error) {
	// Is this a configured domain?
	for _, d := range c.Domains {
		if d.Domain == domain {
			return &d, nil
		}
	}
	return nil, fmt.Errorf("domain not configured")
}

type AliasDomainConfig struct {
	Domain     string        `yaml:"domain"`
	PrivateKey PrivateKey    `yaml:"private_key"`
	PublicKey  PublicKey     `yaml:"public_key"`
	Aliases    []WalletAlias `yaml:"aliases,omitempty"`
}

type LoggingConfig struct {
	Level string `yaml:"level"`
}

type RateLimitConfig struct {
	// Enabled defaults to true when omitted.
	Enabled           *bool `yaml:"enabled,omitempty"`
	RequestsPerMinute int   `yaml:"requests_per_minute,omitempty"`
	Burst             int   `yaml:"burst,omitempty"`
}

type ResolutionConfig struct {
	// TTLSeconds controls how long a per-client resolved address is reused.
	TTLSeconds     int                  `yaml:"ttl_seconds,omitempty"`
	// ClientIdentity determines how "same client" is derived for caching and limits.
	ClientIdentity ClientIdentityConfig `yaml:"client_identity,omitempty"`
}

func (r ResolutionConfig) Clone() ResolutionConfig {
	return ResolutionConfig{
		TTLSeconds:     r.TTLSeconds,
		ClientIdentity: r.ClientIdentity,
	}
}

func (r RateLimitConfig) Clone() RateLimitConfig {
	var enabled *bool
	if r.Enabled != nil {
		v := *r.Enabled
		enabled = &v
	}
	return RateLimitConfig{
		Enabled:           enabled,
		RequestsPerMinute: r.RequestsPerMinute,
		Burst:             r.Burst,
	}
}

func (r RateLimitConfig) EnabledOrDefault() bool {
	if r.Enabled == nil {
		return true
	}
	return *r.Enabled
}

func (a AliasDomainConfig) Clone() AliasDomainConfig {
	return AliasDomainConfig{
		Domain:     a.Domain,
		PrivateKey: PrivateKey(append([]byte(nil), a.PrivateKey...)),
		PublicKey:  PublicKey(append([]byte(nil), a.PublicKey...)),
		Aliases:    append([]WalletAlias(nil), a.Aliases...),
	}
}

func (a *AliasDomainConfig) GenerateKeys() (bool, error) {
	if len(a.PrivateKey) > 0 || len(a.PublicKey) > 0 {
		return false, nil
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return false, err
	}

	a.PrivateKey = PrivateKey(priv)
	a.PublicKey = PublicKey(pub)

	// Logger may not be initialized yet, so use the standard logger here.
	log.Printf("generated keys for domain %s; add DNS TXT: %s", a.Domain, a.DNSTXTRecord())

	return true, nil
}

func (a *AliasDomainConfig) GetJWK() (jwk.Key, error) {
	key, err := jwk.Import(ed25519.PublicKey(a.PublicKey))
	if err != nil {
		return nil, err
	}

	// Set kid to the Cryptalias domain
	if err := key.Set(jwk.KeyIDKey, a.Domain); err != nil {
		return nil, fmt.Errorf("set kid: %w", err)
	}

	return key, nil
}

func (a *AliasDomainConfig) GetSigningJWK() (jwk.Key, error) {
	key, err := jwk.Import(ed25519.PrivateKey(a.PrivateKey))
	if err != nil {
		return nil, err
	}

	// Set kid to the Cryptalias domain
	if err := key.Set(jwk.KeyIDKey, a.Domain); err != nil {
		return nil, fmt.Errorf("set kid: %w", err)
	}

	return key, nil
}

// DNSTXTValue returns the TXT record value that publishes the public key.
func (a *AliasDomainConfig) DNSTXTValue() string {
	return "pubkey=" + base64.StdEncoding.EncodeToString([]byte(a.PublicKey))
}

// DNSTXTRecord returns a ready-to-copy DNS TXT record line.
func (a *AliasDomainConfig) DNSTXTRecord() string {
	return fmt.Sprintf("_cryptalias.%s IN TXT %q", a.Domain, a.DNSTXTValue())
}

type TokenConfig struct {
	Name     string              `yaml:"name"`
	Tickers  []string            `yaml:"tickers"`
	Endpoint TokenEndpointConfig `yaml:"endpoint"`
}

func (t TokenConfig) Clone() TokenConfig {
	return TokenConfig{
		Name:     t.Name,
		Tickers:  append([]string(nil), t.Tickers...),
		Endpoint: t.Endpoint,
	}
}

type TokenEndpointType string

const (
	TokenEndpointTypeInternal = "internal"
	TokenEndpointTypeExternal = "external"
)

type TokenEndpointConfig struct {
	EndpointAddress string            `yaml:"address,omitempty"`
	EndpointType    TokenEndpointType `yaml:"type"`
	// Token/Username/Password are forwarded as auth metadata to external gRPC services.
	Token           string            `yaml:"token,omitempty"`
	Username        string            `yaml:"username,omitempty"`
	Password        string            `yaml:"password,omitempty"`
	// WalletFile/WalletPassword are used by internal integrations (e.g. Monero).
	WalletFile      string            `yaml:"wallet_file,omitempty"`
	WalletPassword  string            `yaml:"wallet_password,omitempty"`
}

func boolPtr(v bool) *bool {
	return &v
}

func normalizeWalletAddress(w *WalletAddress) {
	if w == nil {
		return
	}
	w.Address = strings.TrimSpace(w.Address)
	if w.AccountID != nil {
		v := strings.TrimSpace(*w.AccountID)
		w.AccountID = &v
	}
	if w.WalletID != nil {
		v := strings.TrimSpace(*w.WalletID)
		w.WalletID = &v
	}
}

func LoadOrCreateConfig(path string, defaultCfg *Config) (*Config, error) {
	cfg, err := LoadConfig(path)
	if err == nil {
		return cfg, nil
	}

	// Any errors other than file not found?
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	if err := SaveConfig(path, defaultCfg); err != nil {
		return nil, err
	}

	return defaultCfg, nil
}

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		return nil, err
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	cfg.Normalize(path)

	return &cfg, nil
}

func SaveConfig(path string, cfg *Config) error {
	if cfg == nil {
		return fmt.Errorf("config is nil")
	}
	// Normalize before save so the watcher can re-load without churn.
	cfg.Normalize(path)
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}

	return saveConfigAtomic(path, data)
}
