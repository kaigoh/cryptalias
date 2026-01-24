package cryptalias

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"gopkg.in/yaml.v2"
)

type Config struct {
	BaseURL    string              `yaml:"base_url"`
	PublicPort uint16              `yaml:"public_port"`
	AdminPort  uint16              `yaml:"admin_port"`
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
		AdminPort:  c.AdminPort,
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

func (c *Config) Normalize(path string) {
	c.BaseURL = strings.TrimSuffix(c.BaseURL, "/")
	triggerSave := false
	// Lowercase domains, aliases, tags and tickers
	for i := range c.Domains {
		c.Domains[i].Domain = strings.ToLower(c.Domains[i].Domain)
		for a := range c.Domains[i].Aliases {
			c.Domains[i].Aliases[a].Alias = strings.ToLower(c.Domains[i].Aliases[a].Alias)
			c.Domains[i].Aliases[a].Address.Ticker = strings.ToLower(c.Domains[i].Aliases[a].Address.Ticker)
			for t := range c.Domains[i].Aliases[a].Tags {
				c.Domains[i].Aliases[a].Tags[t].Tag = strings.ToLower(c.Domains[i].Aliases[a].Tags[t].Tag)
				c.Domains[i].Aliases[a].Tags[t].Address.Ticker = strings.ToLower(c.Domains[i].Aliases[a].Tags[t].Address.Ticker)
			}
		}
		if result, err := c.Domains[i].GenerateKeys(); !result && err != nil {
			panic(err)
		} else if result {
			triggerSave = true
		}
	}
	if triggerSave {
		SaveConfig(path, c)
	}
}

func (c *Config) Validate() error {
	if c.BaseURL == "" {
		return fmt.Errorf("base_url is required")
	}
	if c.PublicPort == 0 {
		return fmt.Errorf("public_port must be set")
	}
	if c.AdminPort == 0 {
		return fmt.Errorf("admin_port must be set")
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
			log.Println(t)
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
	Token           string            `yaml:"token,omitempty"`
	Username        string            `yaml:"username,omitempty"`
	Password        string            `yaml:"password,omitempty"`
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
	cfg.Normalize(path)
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}

	return saveConfigAtomic(path, data)
}
