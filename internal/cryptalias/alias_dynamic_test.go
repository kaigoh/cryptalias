package cryptalias

import (
	"context"
	"errors"
	"testing"
)

type fakeResolver struct {
	called bool
	last   dynamicAliasInput
	addr   string
	err    error
}

func (f *fakeResolver) Resolve(_ context.Context, _ *Config, in dynamicAliasInput) (WalletAddress, error) {
	f.called = true
	f.last = in
	if f.err != nil {
		return WalletAddress{}, f.err
	}
	return WalletAddress{Ticker: in.Ticker, Address: f.addr}, nil
}

func TestResolveAliasFallsBackToDynamic(t *testing.T) {
	pub, priv := testKeypair(t)
	cfg := &Config{
		BaseURL:    "http://127.0.0.1:8080",
		PublicPort: 8080,
		AdminPort:  9090,
		Logging:    LoggingConfig{Level: "info"},
		Domains: []AliasDomainConfig{{
			Domain:     "127.0.0.1",
			PublicKey:  pub,
			PrivateKey: priv,
		}},
		Tokens: []TokenConfig{{
			Name:    "Monero",
			Tickers: []string{"xmr"},
			Endpoint: TokenEndpointConfig{
				EndpointType:    TokenEndpointTypeExternal,
				EndpointAddress: "example:50051",
			},
		}},
	}
	cfg.Normalize("")

	resolver := &fakeResolver{addr: "addr-dynamic"}
	alias, err := ResolveAlias(context.Background(), "demo+tip$127.0.0.1", "XMR", cfg, resolver)
	if err != nil {
		t.Fatalf("resolve alias: %v", err)
	}
	if alias.Wallet.Address != "addr-dynamic" {
		t.Fatalf("expected dynamic address, got %q", alias.Wallet.Address)
	}
	if alias.SigningKey == nil {
		t.Fatalf("expected signing key to be attached")
	}
	if !resolver.called {
		t.Fatalf("expected dynamic resolver to be called")
	}
	if resolver.last.Ticker != "xmr" || resolver.last.Alias != "demo" || resolver.last.Tag != "tip" || resolver.last.Domain != "127.0.0.1" {
		t.Fatalf("unexpected dynamic input: %+v", resolver.last)
	}
}

func TestResolveAliasStaticPrecedence(t *testing.T) {
	resolver := &fakeResolver{err: errors.New("should not be called")}
	cfg := testConfig(t)

	alias, err := ResolveAlias(context.Background(), "demo$127.0.0.1", "xmr", cfg, resolver)
	if err != nil {
		t.Fatalf("resolve alias: %v", err)
	}
	if alias.Wallet.Address != "addr-root" {
		t.Fatalf("expected static root address, got %q", alias.Wallet.Address)
	}
	if resolver.called {
		t.Fatalf("expected dynamic resolver not to be called")
	}
}
