package cryptalias

import (
	"fmt"
	"log/slog"
	"net/http"

	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/99designs/gqlgen/graphql/handler/extension"
	"github.com/99designs/gqlgen/graphql/handler/lru"
	"github.com/99designs/gqlgen/graphql/handler/transport"
	"github.com/99designs/gqlgen/graphql/playground"
	"github.com/kaigoh/cryptalias/graph"
	"github.com/vektah/gqlparser/v2/ast"
)

const VERSION = 0

var defaultConfig = &Config{
	BaseURL:    "http://127.0.0.1:8080",
	PublicPort: 8080,
	AdminPort:  9090,
	Logging: LoggingConfig{
		Level: "info",
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

	store := NewConfigStore(configPath, cfg)
	if _, err := WatchConfigFile(configPath, store); err != nil {
		slog.Error("config watcher failed to start", "path", configPath, "error", err)
		return err
	}
	slog.Info("config watcher started", "path", configPath)

	srv := handler.New(graph.NewExecutableSchema(graph.Config{Resolvers: &graph.Resolver{}}))

	srv.AddTransport(transport.Options{})
	srv.AddTransport(transport.GET{})
	srv.AddTransport(transport.POST{})

	srv.SetQueryCache(lru.New[*ast.QueryDocument](1000))

	srv.Use(extension.Introspection{})
	srv.Use(extension.AutomaticPersistedQuery{
		Cache: lru.New[string](100),
	})

	adminMux := http.NewServeMux()
	adminMux.Handle("/", playground.Handler("GraphQL playground", "/query"))
	adminMux.Handle("/query", srv)

	// Public endpoints
	publicMux := http.NewServeMux()
	publicMux.HandleFunc("GET /.well-known/cryptalias", WellKnownHandler(store))
	publicMux.HandleFunc("GET /_cryptalias/keys", JWKSKeysHandler(store))
	publicMux.HandleFunc("GET /_cryptalias/resolve/{ticker}/{alias}", AliasResolverHandler(store))

	adminAddr := fmt.Sprintf(":%d", cfg.AdminPort)
	publicAddr := fmt.Sprintf(":%d", cfg.PublicPort)

	slog.Info("public server listening", "addr", publicAddr, "base_url", cfg.BaseURL)
	slog.Info("private GraphQL playground listening", "addr", adminAddr, "path", "/query")

	errCh := make(chan error, 2)
	go func() {
		errCh <- http.ListenAndServe(publicAddr, publicMux)
	}()
	go func() {
		errCh <- http.ListenAndServe(adminAddr, adminMux)
	}()

	err = <-errCh
	slog.Error("server exited", "error", err)
	return err
}
