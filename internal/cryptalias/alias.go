package cryptalias

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

var re = regexp.MustCompile(`^([A-Za-z0-9.-]+)(?:\+([A-Za-z0-9.-]+))?\$([A-Za-z0-9.-]+)$`)

type Alias struct {
	Alias      string
	Tag        string // Empty if none
	Domain     string
	SigningKey jwk.Key
	Wallet     WalletAddress
}

func ParseAlias(input string, ticker string, config *Config) (Alias, error) {
	inputClean := strings.TrimSpace(input)
	if inputClean == "" {
		return Alias{}, errors.New("empty identifier")
	}

	tickerClean := strings.ToLower(strings.TrimSpace(ticker))
	if tickerClean == "" {
		return Alias{}, errors.New("empty ticker")
	}

	// Normalise for stable matching
	inputClean = strings.ToLower(inputClean)
	m := re.FindStringSubmatch(inputClean)
	if m == nil {
		return Alias{}, errors.New("invalid format (expected alias[+tag]$domain)")
	}

	alias := Alias{
		Alias:  m[1],
		Tag:    m[2],
		Domain: m[3],
	}

	// Validate alias and tag legal characters
	if err := validateAliasOrTag(alias.Alias, "alias"); err != nil {
		return Alias{}, err
	}
	if alias.Tag != "" {
		if err := validateAliasOrTag(alias.Tag, "tag"); err != nil {
			return Alias{}, err
		}
	}

	// Validate domain
	for _, d := range config.Domains {
		if d.Domain == alias.Domain {

			// Attach the domain signing key so the handler can produce a JWS.
			signingKey, err := d.GetSigningJWK()
			if err != nil {
				return Alias{}, err
			}
			alias.SigningKey = signingKey

			// Validate static aliases...
			for _, a := range d.Aliases {
				if a.Alias == alias.Alias {
					// Check tags first...
					for _, t := range a.Tags {
						if t.Tag == alias.Tag && t.Wallet.Ticker == tickerClean {
							alias.Wallet = t.Wallet
							return alias, nil
						}
					}

					// No match, so return the root alias if tickers match...
					if a.Wallet.Ticker == tickerClean {
						alias.Wallet = a.Wallet
						return alias, nil
					}
				}
			}

			// Try and get an address for this alias / tag / ticker / domain combo...
			// ToDo
		}
	}

	return Alias{}, errors.New("unknown alias")
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
