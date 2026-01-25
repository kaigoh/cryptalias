package cryptalias

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	cryptaliasv1 "github.com/kaigoh/cryptalias/proto/cryptalias/v1"
	"google.golang.org/protobuf/proto"
)

type WalletResolver struct {
	state      *AddressStore
	grpc       *grpcWalletClient
	internal   *internalWallets
	internalFn func(ctx context.Context, token TokenConfig, in dynamicAliasInput) (string, error)
	externalFn func(ctx context.Context, token TokenConfig, in dynamicAliasInput) (string, error)
}

// NewWalletResolver wires together state persistence, external gRPC clients,
// and internal wallet integrations.
func NewWalletResolver(configPath string) (*WalletResolver, error) {
	state, err := newAddressStore(configPath)
	if err != nil {
		return nil, err
	}
	return newWalletResolverWithDeps(state, nil, nil), nil
}

func newWalletResolverWithDeps(state *AddressStore, internalFn func(context.Context, TokenConfig, dynamicAliasInput) (string, error), externalFn func(context.Context, TokenConfig, dynamicAliasInput) (string, error)) *WalletResolver {
	r := &WalletResolver{
		state:    state,
		grpc:     newGRPCWalletClient(),
		internal: newInternalWallets(),
	}
	if internalFn != nil {
		r.internalFn = internalFn
	} else {
		r.internalFn = r.resolveInternal
	}
	if externalFn != nil {
		r.externalFn = externalFn
	} else {
		r.externalFn = r.resolveExternal
	}
	return r
}

type dynamicAliasInput struct {
	Ticker       string
	Alias        string
	Tag          string
	Domain       string
	// Optional alias-local routing hints passed through to wallet services.
	AccountIndex *uint64
	AccountID    *string
	WalletID     *string
}

// Resolve performs dynamic resolution via the configured endpoint type and
// enforces per-client TTL caching to reduce address sniffing.
func (r *WalletResolver) Resolve(ctx context.Context, cfg *Config, in dynamicAliasInput) (WalletAddress, error) {
	token, err := findTokenConfig(cfg, in.Ticker)
	if err != nil {
		return WalletAddress{}, err
	}

	clientKey := clientKeyFromContext(ctx)
	now := time.Now().UTC()
	cacheKey := aliasKey(in.Ticker, in.Domain, in.Alias, in.Tag, accountKey(in), clientKey)
	if addr, ok := r.state.Get(cacheKey, now); ok {
		slog.Debug("dynamic resolve cache hit", "ticker", in.Ticker, "domain", in.Domain, "client", clientKey)
		return WalletAddress{Ticker: in.Ticker, Address: addr}, nil
	}

	slog.Debug("dynamic resolve start", "ticker", in.Ticker, "domain", in.Domain, "endpoint_type", token.Endpoint.EndpointType, "client", clientKey)

	var address string
	switch token.Endpoint.EndpointType {
	case TokenEndpointTypeInternal:
		address, err = r.internalFn(ctx, token, in)
	case TokenEndpointTypeExternal:
		address, err = r.externalFn(ctx, token, in)
	default:
		return WalletAddress{}, fmt.Errorf("unsupported endpoint type %q", token.Endpoint.EndpointType)
	}
	if err != nil {
		return WalletAddress{}, err
	}
	if address == "" {
		return WalletAddress{}, fmt.Errorf("wallet resolver returned empty address")
	}
	ttl := time.Duration(cfg.Resolution.TTLSeconds) * time.Second
	if err := r.state.Put(cacheKey, address, clientKey, now, ttl); err != nil {
		slog.Warn("dynamic resolve cache store failed", "error", err)
	}
	return WalletAddress{Ticker: in.Ticker, Address: address}, nil
}

func (r *WalletResolver) resolveInternal(ctx context.Context, token TokenConfig, in dynamicAliasInput) (string, error) {
	switch in.Ticker {
	case "xmr":
		client, err := r.internal.moneroClient(token.Endpoint)
		if err != nil {
			return "", err
		}
		req := &cryptaliasv1.WalletAddressRequest{
			Ticker: in.Ticker,
			Alias:  in.Alias,
			Tag:    in.Tag,
			Domain: in.Domain,
		}
		if in.AccountIndex != nil {
			req.AccountIndex = proto.Uint64(*in.AccountIndex)
		}
		if in.AccountID != nil {
			req.AccountId = proto.String(*in.AccountID)
		}
		if in.WalletID != nil {
			req.WalletId = proto.String(*in.WalletID)
		}
		resp, err := client.GetAddress(ctx, req)
		if err != nil {
			return "", err
		}
		return resp.GetAddress(), nil
	default:
		return "", fmt.Errorf("no internal resolver for ticker %q", in.Ticker)
	}
}

func (r *WalletResolver) resolveExternal(ctx context.Context, token TokenConfig, in dynamicAliasInput) (string, error) {
	return r.grpc.GetAddress(ctx, token.Endpoint, in)
}

func findTokenConfig(cfg *Config, ticker string) (TokenConfig, error) {
	ticker = strings.ToLower(strings.TrimSpace(ticker))
	for _, t := range cfg.Tokens {
		for _, tk := range t.Tickers {
			if strings.ToLower(strings.TrimSpace(tk)) == ticker {
				return t, nil
			}
		}
	}
	return TokenConfig{}, fmt.Errorf("unknown ticker")
}

func accountKey(in dynamicAliasInput) string {
	var parts []string
	if in.AccountIndex != nil {
		parts = append(parts, fmt.Sprintf("ai=%d", *in.AccountIndex))
	}
	if in.AccountID != nil && *in.AccountID != "" {
		parts = append(parts, "aid="+*in.AccountID)
	}
	if in.WalletID != nil && *in.WalletID != "" {
		parts = append(parts, "wid="+*in.WalletID)
	}
	// Empty means "no routing hints" and still participates in the cache key.
	return strings.Join(parts, "|")
}
