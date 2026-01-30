package cryptalias

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

var aliasPattern = regexp.MustCompile(`^(?:([A-Za-z0-9.-]+):)?([A-Za-z0-9.-]+)(?:\+([A-Za-z0-9.-]+))?\$([A-Za-z0-9.-]+)$`)

var (
	ErrAliasNotFound  = errors.New("unknown alias")
	ErrInvalidAlias   = errors.New("invalid alias")
	ErrTickerMismatch = errors.New("ticker mismatch")
)

type walletResolver interface {
	Resolve(ctx context.Context, cfg *Config, in dynamicAliasInput) (WalletAddress, error)
}

type Alias struct {
	Alias      string
	Tag        string // Empty if none
	Domain     string
	SigningKey jwk.Key
	Wallet     WalletAddress
}

// ParseAliasDomain extracts and validates the domain portion of an alias
// identifier without checking whether the domain is configured.
func ParseAliasDomain(input string) (string, error) {
	_, _, _, domain, err := parseAliasParts(input)
	if err != nil {
		return "", err
	}
	return domain, nil
}

// ParseAlias resolves only static mappings from config.
func ParseAlias(input string, ticker string, config *Config) (Alias, error) {
	alias, domainCfg, tickerClean, err := parseAliasIdentifier(input, ticker, config)
	if err != nil {
		return Alias{}, err
	}
	walletCfg, ok := findAliasWallet(domainCfg, alias.Alias, alias.Tag, tickerClean)
	if ok && strings.TrimSpace(walletCfg.Address) != "" {
		alias.Wallet = walletCfg
		return alias, nil
	}
	return Alias{}, ErrAliasNotFound
}

// ResolveAlias prefers static mappings, then falls back to dynamic resolution.
// When a static alias exists but has no address, its optional routing hints
// (account_index/account_id/wallet_id) are forwarded to the wallet service.
func ResolveAlias(ctx context.Context, input string, ticker string, cfg *Config, resolver walletResolver) (Alias, error) {
	alias, domainCfg, tickerClean, err := parseAliasIdentifier(input, ticker, cfg)
	if err != nil {
		return Alias{}, err
	}
	walletCfg, ok := findAliasWallet(domainCfg, alias.Alias, alias.Tag, tickerClean)
	if ok && strings.TrimSpace(walletCfg.Address) != "" {
		alias.Wallet = walletCfg
		return alias, nil
	}
	if resolver == nil {
		return Alias{}, ErrAliasNotFound
	}

	in := dynamicAliasInput{
		Ticker: tickerClean,
		Alias:  alias.Alias,
		Tag:    alias.Tag,
		Domain: alias.Domain,
	}
	if ok {
		in.AccountIndex = walletCfg.AccountIndex
		in.AccountID = walletCfg.AccountID
		in.WalletID = walletCfg.WalletID
	}

	wallet, err := resolver.Resolve(ctx, cfg, in)
	if err != nil {
		return Alias{}, err
	}

	alias.Wallet = wallet
	return alias, nil
}

func parseAliasIdentifier(input string, ticker string, cfg *Config) (Alias, AliasDomainConfig, string, error) {
	inputClean := strings.TrimSpace(input)
	if inputClean == "" {
		return Alias{}, AliasDomainConfig{}, "", fmt.Errorf("%w: empty identifier", ErrInvalidAlias)
	}

	tickerClean := strings.ToLower(strings.TrimSpace(ticker))
	if tickerClean == "" {
		return Alias{}, AliasDomainConfig{}, "", fmt.Errorf("%w: empty ticker", ErrInvalidAlias)
	}

	prefixTicker, aliasName, tag, domain, err := parseAliasParts(inputClean)
	if err != nil {
		return Alias{}, AliasDomainConfig{}, "", err
	}
	if prefixTicker != "" && prefixTicker != tickerClean {
		return Alias{}, AliasDomainConfig{}, "", fmt.Errorf("%w: prefix %q does not match %q", ErrTickerMismatch, prefixTicker, tickerClean)
	}

	alias := Alias{
		Alias:  aliasName,
		Tag:    tag,
		Domain: domain,
	}

	for _, d := range cfg.Domains {
		if d.Domain != alias.Domain {
			continue
		}
		signingKey, err := d.GetSigningJWK()
		if err != nil {
			return Alias{}, AliasDomainConfig{}, "", err
		}
		alias.SigningKey = signingKey
		return alias, d, tickerClean, nil
	}

	return Alias{}, AliasDomainConfig{}, "", ErrAliasNotFound
}

func parseAliasParts(input string) (string, string, string, string, error) {
	inputClean := strings.ToLower(strings.TrimSpace(input))
	if inputClean == "" {
		return "", "", "", "", fmt.Errorf("%w: empty identifier", ErrInvalidAlias)
	}
	m := aliasPattern.FindStringSubmatch(inputClean)
	if m == nil {
		return "", "", "", "", fmt.Errorf("%w: invalid format (expected [ticker:]alias[+tag]$domain)", ErrInvalidAlias)
	}

	prefixTicker := m[1]
	alias := m[2]
	tag := m[3]
	domain := m[4]

	if prefixTicker != "" {
		if err := validateAliasOrTag(prefixTicker, "ticker"); err != nil {
			return "", "", "", "", fmt.Errorf("%w: %v", ErrInvalidAlias, err)
		}
	}
	if err := validateAliasOrTag(alias, "alias"); err != nil {
		return "", "", "", "", fmt.Errorf("%w: %v", ErrInvalidAlias, err)
	}
	if tag != "" {
		if err := validateAliasOrTag(tag, "tag"); err != nil {
			return "", "", "", "", fmt.Errorf("%w: %v", ErrInvalidAlias, err)
		}
	}

	return prefixTicker, alias, tag, domain, nil
}

func findAliasWallet(domainCfg AliasDomainConfig, aliasName, tag, tickerClean string) (WalletAddress, bool) {
	for _, a := range domainCfg.Aliases {
		if a.Alias != aliasName {
			continue
		}
		// Check tags first.
		for _, t := range a.Tags {
			if t.Tag == tag && t.Wallet.Ticker == tickerClean {
				return t.Wallet, true
			}
		}
		// Fall back to the root alias if tickers match.
		if a.Wallet.Ticker == tickerClean {
			return a.Wallet, true
		}
	}
	return WalletAddress{}, false
}

func validateAliasOrTag(s, field string) error {
	if s == "" {
		return fmt.Errorf("%s is empty", field)
	}

	// Check the first character is alphanumeric
	isAlnum := func(b byte) bool {
		return (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9')
	}
	if !isAlnum(s[0]) || !isAlnum(s[len(s)-1]) {
		return fmt.Errorf("%s must start and end with a letter or digit", field)
	}
	if strings.Contains(s, "..") {
		return fmt.Errorf("%s must not contain consecutive dots", field)
	}

	return nil
}
