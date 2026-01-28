package cryptaliasclient

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type wellKnownConfig struct {
	Resolver struct {
		ResolverEndpoint string `json:"resolver_endpoint"`
	} `json:"resolver"`
	Key jwkKey `json:"key"`
}

type resolvedPayload struct {
	Address string `json:"address"`
	Expires string `json:"expires"`
}

type jwkKey struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
}

// ResolveAddress resolves alias$domain into a wallet address and verifies the JWS signature.
func ResolveAddress(ctx context.Context, ticker, alias string) (string, error) {
	if ticker == "" || alias == "" {
		return "", errors.New("ticker and alias are required")
	}
	domain, err := parseDomain(alias)
	if err != nil {
		return "", err
	}

	cfgURL := fmt.Sprintf("https://%s/.well-known/cryptalias/configuration", domain)
	cfgBody, err := httpGet(ctx, cfgURL, "application/json")
	if err != nil {
		return "", err
	}

	var cfg wellKnownConfig
	if err := json.Unmarshal(cfgBody, &cfg); err != nil {
		return "", err
	}
	resolver := strings.TrimRight(cfg.Resolver.ResolverEndpoint, "/")
	if resolver == "" {
		return "", errors.New("missing resolver_endpoint in configuration")
	}
	if cfg.Key.X == "" {
		return "", errors.New("missing key in configuration")
	}

	resolveURL := fmt.Sprintf("%s/_cryptalias/resolve/%s/%s", resolver, url.PathEscape(ticker), url.PathEscape(alias))
	jws, err := httpGet(ctx, resolveURL, "application/jose")
	if err != nil {
		return "", err
	}

	payload, err := verifyJwsAndDecodePayload(string(jws), cfg.Key)
	if err != nil {
		return "", err
	}
	if err := enforceExpires(payload.Expires); err != nil {
		return "", err
	}
	return payload.Address, nil
}

func parseDomain(alias string) (string, error) {
	idx := strings.LastIndex(alias, "$")
	if idx == -1 || idx == len(alias)-1 {
		return "", errors.New("alias must be in the format alias$domain")
	}
	return alias[idx+1:], nil
}

func httpGet(ctx context.Context, urlStr, accept string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", accept)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return nil, fmt.Errorf("request failed %d: %s", res.StatusCode, strings.TrimSpace(string(body)))
	}
	return body, nil
}

func decodeJWSPayload(jws string) (resolvedPayload, error) {
	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		return resolvedPayload{}, errors.New("invalid JWS format")
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return resolvedPayload{}, err
	}
	var payload resolvedPayload
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return resolvedPayload{}, err
	}
	if payload.Address == "" {
		return resolvedPayload{}, errors.New("missing address in JWS payload")
	}
	return payload, nil
}

func verifyJwsAndDecodePayload(jws string, key jwkKey) (resolvedPayload, error) {
	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		return resolvedPayload{}, errors.New("invalid JWS format")
	}
	signingInput := []byte(parts[0] + "." + parts[1])
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return resolvedPayload{}, err
	}
	pubBytes, err := base64.RawURLEncoding.DecodeString(key.X)
	if err != nil {
		return resolvedPayload{}, err
	}
	if len(pubBytes) != ed25519.PublicKeySize {
		return resolvedPayload{}, errors.New("invalid public key length")
	}
	pub := ed25519.PublicKey(pubBytes)
	if !ed25519.Verify(pub, signingInput, sig) {
		return resolvedPayload{}, errors.New("signature verification failed")
	}
	return decodeJWSPayload(jws)
}

func enforceExpires(value string) error {
	if strings.TrimSpace(value) == "" {
		return errors.New("missing expires in JWS payload")
	}
	expires, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return errors.New("invalid expires in JWS payload")
	}
	if !expires.After(time.Now().UTC()) {
		return errors.New("resolved address has expired")
	}
	return nil
}
