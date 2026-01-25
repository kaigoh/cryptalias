package cryptalias

import (
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

type limiterEntry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

type rateLimitSnapshot struct {
	enabled  bool
	rpm      int
	burst    int
	strategy ClientIdentityStrategy
	header   string
}

type rateLimiter struct {
	mu       sync.Mutex
	store    *ConfigStore
	limit    rate.Limit
	burst    int
	identity *clientIdentity
	current  rateLimitSnapshot
	entries  map[string]*limiterEntry
}

func newRateLimiter(store *ConfigStore) *rateLimiter {
	if store == nil {
		return nil
	}
	return &rateLimiter{
		store:   store,
		entries: map[string]*limiterEntry{},
	}
}

func (rl *rateLimiter) middleware(next http.Handler) http.Handler {
	if rl == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg := rl.store.Get()
		snap := snapshotFromConfig(cfg)
		if !snap.enabled {
			next.ServeHTTP(w, r)
			return
		}
		rl.refreshIfNeeded(snap)

		client := rl.identity.Key(r)
		if !rl.allow(client) {
			slog.Warn("rate limit exceeded", "client", client, "path", r.URL.Path)
			w.WriteHeader(http.StatusTooManyRequests)
			fmt.Fprint(w, "429 too many requests")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func snapshotFromConfig(cfg *Config) rateLimitSnapshot {
	ci := cfg.Resolution.ClientIdentity
	return rateLimitSnapshot{
		enabled:  cfg.RateLimit.EnabledOrDefault(),
		rpm:      cfg.RateLimit.RequestsPerMinute,
		burst:    cfg.RateLimit.Burst,
		strategy: ci.Strategy,
		header:   ci.Header,
	}
}

func (rl *rateLimiter) refreshIfNeeded(next rateLimitSnapshot) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	if rl.current == next && rl.identity != nil {
		return
	}
	perSecond := float64(next.rpm) / 60.0
	rl.limit = rate.Limit(perSecond)
	rl.burst = next.burst
	rl.identity = newClientIdentity(ClientIdentityConfig{Strategy: next.strategy, Header: next.header})
	rl.current = next
	// Limits or identity changed; reset per-client state to avoid drift.
	rl.entries = map[string]*limiterEntry{}
	slog.Info("rate limiter configuration updated", "rpm", next.rpm, "burst", next.burst, "strategy", next.strategy)
}

func (rl *rateLimiter) allow(client string) bool {
	now := time.Now().UTC()

	rl.mu.Lock()
	defer rl.mu.Unlock()

	entry, ok := rl.entries[client]
	if !ok {
		entry = &limiterEntry{limiter: rate.NewLimiter(rl.limit, rl.burst)}
		rl.entries[client] = entry
	}
	entry.lastSeen = now

	// Lazy cleanup to avoid unbounded growth without a background timer.
	if len(rl.entries) > 4096 {
		cutoff := now.Add(-10 * time.Minute)
		for k, v := range rl.entries {
			if v.lastSeen.Before(cutoff) {
				delete(rl.entries, k)
			}
		}
	}

	return entry.limiter.Allow()
}
