package main

import (
	"context"
	"flag"
	"log"
	"os/signal"
	"syscall"

	"github.com/cjmustard/console-connect"
)

func main() {
	listenAddr := flag.String("listen", "", "override listener address for bedrock clients")
	flag.Parse()

	opts := consoleconnect.Options{}
	opts.ApplyDefaults()
	if listenAddr != nil && *listenAddr != "" {
		opts.Listener.Address = *listenAddr
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	svc, err := consoleconnect.New(opts)
	if err != nil {
		log.Fatalf("initialise broadcaster: %v", err)
	}

	if err := svc.Run(ctx); err != nil {
		log.Fatalf("broadcaster stopped: %v", err)
	}
}
