package main

import (
	"flag"
	"log"

	"github.com/jedisct1/whatsmyresolver/pkg/resolver"
)

var (
	address = flag.String("listen", ":53", "Address to listen to (UDP)")
)

func main() {
	flag.Parse()

	server := resolver.New(*address)
	if err := server.Start(); err != nil {
		log.Fatal(err)
	}
}

