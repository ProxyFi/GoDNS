// cmd/main.go
package main

import (
	// Import the godns package to make its functionality available.
	// This allows us to call the godns.main() function from here.
	"github.com/ProxyFi/GoDNS"
)

// main is the entry point for the executable.
// It directly calls the main function from the imported godns package.
// This design pattern separates the package logic (godns) from the
// executable entry point (cmd/main.go).
func main() {
	godns.main()
}
