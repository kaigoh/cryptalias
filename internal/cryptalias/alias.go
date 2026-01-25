package cryptalias

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

var re = regexp.MustCompile(`^([A-Za-z0-9.-]+)(?:\+([A-Za-z0-9.-]+))?\$([A-Za-z0-9.-]+)$`)

var ErrAliasNotFound = errors.New("unknown alias")

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

func ParseAlias(input string, ticker string, config *Config) (Alias, error) {
	alias, domainCfg, tickerClean, err := parseAliasIdentifier(input, ticker, config)
	if err != nil {
		return Alias{}, err
	}
	if tryStaticResolution(&alias, domainCfg, tickerClean) {
		return alias, nil
	}
	return Alias{}, ErrAliasNotFound
}

func ResolveAlias(ctx context.Context, input string, ticker string, cfg *Config, resolver walletResolver) (Alias, error) {
	alias, domainCfg, tickerClean, err := parseAliasIdentifier(input, ticker, cfg)
	if err != nil {
		return Alias{}, err
	}
	if tryStaticResolution(&alias, domainCfg, tickerClean) {
		return alias, nil
	}
	if resolver == nil {
		return Alias{}, ErrAliasNotFound
	}

	wallet, err := resolver.Resolve(ctx, cfg, dynamicAliasInput{
		Ticker: tickerClean,
		Alias:  alias.Alias,
		Tag:    alias.Tag,
		Domain: alias.Domain,
	})
	if err != nil {
		return Alias{}, err
	}

	alias.Wallet = wallet
	return alias, nil
}

func parseAliasIdentifier(input string, ticker string, cfg *Config) (Alias, AliasDomainConfig, string, error) {
	inputClean := strings.TrimSpace(input)
	if inputClean == "" {
		return Alias{}, AliasDomainConfig{}, "", errors.New("empty identifier")
	}

	tickerClean := strings.ToLower(strings.TrimSpace(ticker))
	if tickerClean == "" {
		return Alias{}, AliasDomainConfig{}, "", errors.New("empty ticker")
	}

	// Normalise for stable matching
	inputClean = strings.ToLower(inputClean)
	m := re.FindStringSubmatch(inputClean)
	if m == nil {
		return Alias{}, AliasDomainConfig{}, "", errors.New("invalid format (expected alias[+tag]$domain)")
	}

	alias := Alias{
		Alias:  m[1],
		Tag:    m[2],
		Domain: m[3],
	}

	// Validate alias and tag legal characters
	if err := validateAliasOrTag(alias.Alias, "alias"); err != nil {
		return Alias{}, AliasDomainConfig{}, "", err
	}
	if alias.Tag != "" {
		if err := validateAliasOrTag(alias.Tag, "tag"); err != nil {
			return Alias{}, AliasDomainConfig{}, "", err
		}
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

func tryStaticResolution(alias *Alias, domainCfg AliasDomainConfig, tickerClean string) bool {
	for _, a := range domainCfg.Aliases {
		if a.Alias != alias.Alias {
			continue
		}
		// Check tags first.
		for _, t := range a.Tags {
			if t.Tag == alias.Tag && t.Wallet.Ticker == tickerClean {
				alias.Wallet = t.Wallet
				return true
			}
		}
		// Fall back to the root alias if tickers match.
		if a.Wallet.Ticker == tickerClean {
			alias.Wallet = a.Wallet
			return true
		}
	}
	return false
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
