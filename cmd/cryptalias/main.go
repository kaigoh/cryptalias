package main

import (
	"log"
	"os"

	"github.com/kaigoh/cryptalias/internal/cryptalias"
)

func main() {
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
