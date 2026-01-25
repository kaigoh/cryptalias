package cryptalias

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/http"
	"strings"
)

type clientKeyContextKey struct{}

type ClientIdentityStrategy string

const (
	ClientIdentityStrategyRemoteAddr ClientIdentityStrategy = "remote_address"
	ClientIdentityStrategyXFF        ClientIdentityStrategy = "xff"
	ClientIdentityStrategyXFFUA      ClientIdentityStrategy = "xff_ua"
	ClientIdentityStrategyHeader     ClientIdentityStrategy = "header"
	ClientIdentityStrategyHeaderUA   ClientIdentityStrategy = "header_ua"
)

type ClientIdentityConfig struct {
	Strategy ClientIdentityStrategy `yaml:"strategy,omitempty"`
	Header   string                 `yaml:"header,omitempty"`
}

// clientIdentity derives a stable per-client key used for both caching and rate limiting.
type clientIdentity struct {
	strategy ClientIdentityStrategy
	header   string
}

func newClientIdentity(cfg ClientIdentityConfig) *clientIdentity {
	strategy := cfg.Strategy
	if strategy == "" {
		strategy = ClientIdentityStrategyXFF
	}
	header := strings.TrimSpace(cfg.Header)
	if header == "" {
		header = "X-Forwarded-For"
	}
	return &clientIdentity{strategy: strategy, header: header}
}

func withClientKey(ctx context.Context, key string) context.Context {
	return context.WithValue(ctx, clientKeyContextKey{}, key)
}

// clientKeyFromContext is used by the resolver so client identity computed in the
// HTTP layer can flow through to the wallet resolution cache.
func clientKeyFromContext(ctx context.Context) string {
	if ctx == nil {
		return "unknown"
	}
	if v, ok := ctx.Value(clientKeyContextKey{}).(string); ok && v != "" {
		return v
	}
	return "unknown"
}

func (ci *clientIdentity) Key(r *http.Request) string {
	if r == nil {
		return "unknown"
	}
	base := ci.baseKey(r)
	if base == "" {
		base = remoteAddrKey(r)
	}
	switch ci.strategy {
	case ClientIdentityStrategyXFFUA, ClientIdentityStrategyHeaderUA:
		return base + "|ua:" + hashUA(r.UserAgent())
	default:
		return base
	}
}

func (ci *clientIdentity) baseKey(r *http.Request) string {
	switch ci.strategy {
	case ClientIdentityStrategyRemoteAddr:
		return remoteAddrKey(r)
	case ClientIdentityStrategyHeader, ClientIdentityStrategyHeaderUA:
		return headerKey(r, ci.header)
	case ClientIdentityStrategyXFF, ClientIdentityStrategyXFFUA:
		return xffKey(r)
	default:
		return xffKey(r)
	}
}

func headerKey(r *http.Request, header string) string {
	v := strings.TrimSpace(r.Header.Get(header))
	if v == "" {
		return ""
	}
	// Support comma-separated headers by taking the first entry.
	if strings.Contains(v, ",") {
		parts := strings.Split(v, ",")
		v = strings.TrimSpace(parts[0])
	}
	return v
}

func xffKey(r *http.Request) string {
	v := headerKey(r, "X-Forwarded-For")
	if v != "" {
		return v
	}
	// Fall back to common proxy headers before remote addr.
	if xr := headerKey(r, "X-Real-IP"); xr != "" {
		return xr
	}
	return ""
}

func remoteAddrKey(r *http.Request) string {
	host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err == nil && host != "" {
		return host
	}
	if r.RemoteAddr != "" {
		return strings.TrimSpace(r.RemoteAddr)
	}
	return "unknown"
}

func hashUA(ua string) string {
	ua = strings.TrimSpace(ua)
	if ua == "" {
		return "none"
	}
	sum := sha256.Sum256([]byte(ua))
	// Keep keys compact and avoid persisting raw user agents.
	return hex.EncodeToString(sum[:8])
}
