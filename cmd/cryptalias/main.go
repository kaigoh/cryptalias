package main

import (
	"log"
	"os"
	"os/user"

	"github.com/kaigoh/cryptalias/internal/cryptalias"
)

func main() {
	// We DON'T want to be running as root...
	user, err := user.Current()
	if err != nil {
		log.Fatalf("Unable to check user account we're running under! %s", err)
	}
	if user.Username == "root" || user.Username == "Administrator" {
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
