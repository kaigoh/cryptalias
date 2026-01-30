package cryptalias

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func testKeypair(t *testing.T) (PublicKey, PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate keypair: %v", err)
	}
	return PublicKey(pub), PrivateKey(priv)
}

func testConfig(t *testing.T) *Config {
	t.Helper()
	pub, priv := testKeypair(t)
	cfg := &Config{
		BaseURL:    "http://127.0.0.1:8080/",
		PublicPort: 8080,
		Logging:    LoggingConfig{Level: "WARN"},
		Domains: []AliasDomainConfig{
			{
				Domain:     "127.0.0.1",
				PublicKey:  pub,
				PrivateKey: priv,
				Aliases: []WalletAlias{
					{
						Alias: "Demo",
						Wallet: WalletAddress{
							Ticker:  "XMR",
							Address: "addr-root",
						},
						Tags: []WalletTag{
							{
								Tag: "Tip",
								Wallet: WalletAddress{
									Ticker:  "XMR",
									Address: "addr-tag",
								},
							},
						},
					},
				},
			},
		},
		Tokens: []TokenConfig{
			{
				Name:    "Monero",
				Tickers: []string{"xmr"},
				Endpoint: TokenEndpointConfig{
					EndpointType:    TokenEndpointTypeExternal,
					EndpointAddress: "cryptalias-monero:50051",
				},
			},
		},
	}
	cfg.Normalize("")
	return cfg
}

func TestNormalizeLowercasesAndDefaults(t *testing.T) {
	cfg := testConfig(t)

	if cfg.BaseURL != "http://127.0.0.1:8080" {
		t.Fatalf("expected trimmed base_url, got %q", cfg.BaseURL)
	}
	if cfg.Logging.Level != "warn" {
		t.Fatalf("expected normalized log level warn, got %q", cfg.Logging.Level)
	}
	if got := cfg.Domains[0].Aliases[0].Alias; got != "demo" {
		t.Fatalf("expected alias to be lowercased, got %q", got)
	}
	if got := cfg.Domains[0].Aliases[0].Wallet.Ticker; got != "xmr" {
		t.Fatalf("expected ticker to be lowercased, got %q", got)
	}
	if got := cfg.Domains[0].Aliases[0].Tags[0].Tag; got != "tip" {
		t.Fatalf("expected tag to be lowercased, got %q", got)
	}
}

func TestValidateRejectsInvalidLogLevel(t *testing.T) {
	cfg := testConfig(t)
	cfg.Logging.Level = "verbose"

	if err := cfg.Validate(); err == nil {
		t.Fatalf("expected invalid logging.level to fail validation")
	}
}

func TestParseAliasResolvesRootAndTag(t *testing.T) {
	cfg := testConfig(t)

	root, err := ParseAlias("Demo$127.0.0.1", "XMR", cfg)
	if err != nil {
		t.Fatalf("parse root alias: %v", err)
	}
	if root.Wallet.Address != "addr-root" {
		t.Fatalf("expected root address addr-root, got %q", root.Wallet.Address)
	}
	if root.SigningKey == nil {
		t.Fatalf("expected signing key to be attached")
	}

	tagged, err := ParseAlias("demo+tip$127.0.0.1", "xmr", cfg)
	if err != nil {
		t.Fatalf("parse tagged alias: %v", err)
	}
	if tagged.Wallet.Address != "addr-tag" {
		t.Fatalf("expected tagged address addr-tag, got %q", tagged.Wallet.Address)
	}
}

func TestParseAliasUnknownTicker(t *testing.T) {
	cfg := testConfig(t)

	if _, err := ParseAlias("demo$127.0.0.1", "btc", cfg); err == nil {
		t.Fatalf("expected unknown ticker to return an error")
	}
}

func TestParseAliasAcceptsTickerPrefix(t *testing.T) {
	cfg := testConfig(t)

	alias, err := ParseAlias("xmr:demo$127.0.0.1", "xmr", cfg)
	if err != nil {
		t.Fatalf("parse alias with prefix: %v", err)
	}
	if alias.Wallet.Address != "addr-root" {
		t.Fatalf("expected root address addr-root, got %q", alias.Wallet.Address)
	}
}

func TestParseAliasTickerPrefixMismatch(t *testing.T) {
	cfg := testConfig(t)

	if _, err := ParseAlias("btc:demo$127.0.0.1", "xmr", cfg); err == nil {
		t.Fatalf("expected prefix mismatch to return an error")
	}
}
