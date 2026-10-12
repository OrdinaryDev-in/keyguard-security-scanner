// Command mkfixture writes the fake vulnerable demo app: go run ./cmd/mkfixture /tmp/demo-app
package main

import (
	"fmt"
	"os"

	"keyguard/internal/fixture"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: mkfixture <dir>")
		os.Exit(2)
	}
	if err := fixture.Write(os.Args[1]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println("wrote demo app to", os.Args[1])
}
