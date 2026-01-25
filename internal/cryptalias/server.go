package cryptalias

import (
	"fmt"
	"log/slog"
	"net/http"
)

const VERSION = 0

var defaultConfig = &Config{
	BaseURL:    "http://127.0.0.1:8080",
	PublicPort: 8080,
	Logging: LoggingConfig{
		Level: "info",
	},
	RateLimit: RateLimitConfig{
		Enabled:           boolPtr(true),
		RequestsPerMinute: 60,
		Burst:             10,
	},
	Resolution: ResolutionConfig{
		TTLSeconds: 60,
		ClientIdentity: ClientIdentityConfig{
			Strategy: ClientIdentityStrategyXFF,
			Header:   "X-Forwarded-For",
		},
	},
	Domains: []AliasDomainConfig{
		{Domain: "127.0.0.1"},
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

func Run(configPath string) error {
	if configPath == "" {
		configPath = "config.yml"
	}

	cfg, err := LoadOrCreateConfig(configPath, defaultConfig)
	if err != nil {
		return err
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	InitLogger(cfg.Logging)
	slog.Info("config loaded", "path", configPath, "base_url", cfg.BaseURL)
	for _, d := range cfg.Domains {
		slog.Info("dns txt record", "domain", d.Domain, "name", "_cryptalias."+d.Domain, "value", d.DNSTXTValue())
	}

	store := NewConfigStore(configPath, cfg)
	resolver, err := NewWalletResolver(configPath)
	if err != nil {
		slog.Error("wallet resolver failed to start", "error", err)
		return err
	}
	if _, err := WatchConfigFile(configPath, store); err != nil {
		slog.Error("config watcher failed to start", "path", configPath, "error", err)
		return err
	}
	slog.Info("config watcher started", "path", configPath)

	// Public endpoints only.
	publicMux := http.NewServeMux()
	publicMux.HandleFunc("GET /.well-known/cryptalias", WellKnownHandler(store))
	publicMux.HandleFunc("GET /_cryptalias/keys", JWKSKeysHandler(store))

	resolveHandler := http.Handler(AliasResolverHandler(store, resolver))
	resolveHandler = newRateLimiter(store).middleware(resolveHandler)
	publicMux.Handle("GET /_cryptalias/resolve/{ticker}/{alias}", resolveHandler)

	publicAddr := fmt.Sprintf(":%d", cfg.PublicPort)

	slog.Info("public server listening", "addr", publicAddr, "base_url", cfg.BaseURL)

	if err := http.ListenAndServe(publicAddr, publicMux); err != nil {
		slog.Error("server exited", "error", err)
		return err
	}
	return nil
}
