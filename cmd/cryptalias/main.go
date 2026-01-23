package main

import (
	"log"
	"os"

	"github.com/kaigoh/cryptalias/internal/cryptalias"
)

func main() {
	configPath := "config.yml"
	if len(os.Args) > 1 && os.Args[1] != "" {
		configPath = os.Args[1]
	}

	if err := cryptalias.Run(configPath); err != nil {
		log.Fatal(err)
	}
}
