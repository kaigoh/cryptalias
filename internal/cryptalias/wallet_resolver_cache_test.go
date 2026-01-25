package cryptalias

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
)

func TestWalletResolverCachesPerClient(t *testing.T) {
	dir := t.TempDir()
	state, err := newAddressStore(filepath.Join(dir, "config.yml"))
	if err != nil {
		t.Fatalf("new address store: %v", err)
	}

	calls := 0
	internalFn := func(ctx context.Context, token TokenConfig, in dynamicAliasInput) (string, error) {
		calls++
		return fmt.Sprintf("addr-%d", calls), nil
	}
	resolver := newWalletResolverWithDeps(state, internalFn, nil)

	cfg := &Config{
		Tokens: []TokenConfig{
			{
				Name:    "Monero",
				Tickers: []string{"xmr"},
				Endpoint: TokenEndpointConfig{
					EndpointType:    TokenEndpointTypeInternal,
					EndpointAddress: "internal",
				},
			},
		},
	}
	cfg.Normalize("")

	in := dynamicAliasInput{Ticker: "xmr", Alias: "demo", Domain: "example.com"}

	ctxA := withClientKey(context.Background(), "client-a")
	first, err := resolver.Resolve(ctxA, cfg, in)
	if err != nil {
		t.Fatalf("first resolve: %v", err)
	}
	second, err := resolver.Resolve(ctxA, cfg, in)
	if err != nil {
		t.Fatalf("second resolve: %v", err)
	}
	if first.Address != second.Address {
		t.Fatalf("expected cached address for same client, got %q then %q", first.Address, second.Address)
	}
	if calls != 1 {
		t.Fatalf("expected 1 internal call for same client, got %d", calls)
	}

	ctxB := withClientKey(context.Background(), "client-b")
	third, err := resolver.Resolve(ctxB, cfg, in)
	if err != nil {
		t.Fatalf("third resolve: %v", err)
	}
	if third.Address == first.Address {
		t.Fatalf("expected different clients to get different addresses, got %q", third.Address)
	}
	if calls != 2 {
		t.Fatalf("expected 2 internal calls after different client, got %d", calls)
	}
}
