package main

import (
	"fmt"
	"log"
	"os"

	"udp2raw-go/internal/config"
	"udp2raw-go/internal/tunnel"
)

func main() {
	cfg, err := config.Parse(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to parse args: %v\n", err)
		os.Exit(1)
	}

	logger := log.New(os.Stdout, "", log.LstdFlags)
	logger.Printf("starting udp2raw-go in %s mode", modeName(cfg.Mode))
	if cfg.RawMode != "udp" {
		logger.Printf("warning: raw mode %s is accepted but currently uses UDP transport; advanced raw headers are not yet implemented", cfg.RawMode)
	}

	if err := tunnel.Run(cfg, logger); err != nil {
		logger.Printf("fatal: %v", err)
		os.Exit(1)
	}
}

func modeName(m config.Mode) string {
	if m == config.Client {
		return "client"
	}
	return "server"
}
