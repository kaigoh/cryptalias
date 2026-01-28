package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/kaigoh/cryptalias/internal/cryptalias"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "resolve" {
		if err := runResolve(os.Args[2:]); err != nil {
			log.Fatal(err)
		}
		return
	}

	// We DON'T want to be running as root...
	if os.Getuid() == 0 {
		log.Fatalf("Don't run cryptalias as root!")
	}

	configPath := "config.yml"
	if len(os.Args) > 1 && os.Args[1] != "" {
		configPath = os.Args[1]
	}

	if err := cryptalias.Run(configPath); err != nil {
		log.Fatal(err)
	}
}

func runResolve(args []string) error {
	flags := flag.NewFlagSet("resolve", flag.ContinueOnError)
	jsonOut := flags.Bool("json", false, "output JSON")
	if err := flags.Parse(args); err != nil {
		return err
	}
	rest := flags.Args()
	if len(rest) != 2 {
		return fmt.Errorf("usage: cryptalias resolve [--json] <alias$domain> <ticker>")
	}
	alias := strings.TrimSpace(rest[0])
	ticker := strings.TrimSpace(rest[1])
	if alias == "" || ticker == "" {
		return fmt.Errorf("alias and ticker are required")
	}
	if !strings.Contains(alias, "$") {
		return fmt.Errorf("alias must be in the format alias$domain (tip: wrap in single quotes to avoid shell expansion)")
	}

	address, err := cryptalias.ResolveAddress(context.Background(), ticker, alias)
	if err != nil {
		return err
	}

	if *jsonOut {
		output := struct {
			Alias   string `json:"alias"`
			Ticker  string `json:"ticker"`
			Address string `json:"address"`
		}{
			Alias:   alias,
			Ticker:  strings.ToLower(ticker),
			Address: address,
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(output)
	}

	_, err = fmt.Fprintf(os.Stdout, "%s %s\n", strings.ToLower(ticker), address)
	return err
}
