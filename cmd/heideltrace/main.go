//go:build linux

// Command heideltrace is an eBPF observability agent for LLM inference
// servers. See README.md for usage.
package main

import (
	"context"
	"errors"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/sonix03/heideltrace/internal/agent"
	"github.com/sonix03/heideltrace/internal/config"
)

func main() {
	logger := log.New(os.Stderr, "[heideltrace] ", 0)

	cfg, err := config.Parse(os.Args[1:], os.Stderr)
	if errors.Is(err, config.ErrHelp) {
		return
	}
	if err != nil {
		logger.Printf("%v (see --help)", err)
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if cfg.Duration > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, cfg.Duration)
		defer cancel()
	}

	if err := agent.Run(ctx, cfg, logger); err != nil {
		logger.Printf("%v", err)
		os.Exit(1)
	}
}
