package main

import (
	"fmt"
	"os"

	"github.com/go-oauth2/oauth2/v4/seed"
)

func main() {
	if err := seed.RunFromEnv(); err != nil {
		fmt.Fprintf(os.Stderr, "seed failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("seed completed successfully")
}
