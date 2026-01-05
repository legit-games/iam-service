package main

import (
	"fmt"
	"os"

	"github.com/go-oauth2/oauth2/v4/migrate"
)

func main() {
	if err := migrate.RunFromEnv(); err != nil {
		fmt.Fprintf(os.Stderr, "migrate failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("migrate completed successfully")
}
