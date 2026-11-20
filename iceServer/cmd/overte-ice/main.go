package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/overte-org/overte-ice-server/internal/config"
	"github.com/overte-org/overte-ice-server/internal/server"
)

func main() {
	configPath := flag.String("config", "/etc/overte-ice/config.json", "path to configuration JSON")
	flag.Parse()
	cfg, e := config.Load(*configPath)
	if e != nil {
		log.Fatalf("configuration: %v", e)
	}
	srv, e := server.New(cfg)
	if e != nil {
		log.Fatalf("initialize: %v", e)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if e = srv.Run(ctx); e != nil {
		log.Fatalf("server stopped: %v", e)
	}
}
