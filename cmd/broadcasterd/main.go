package main

import (
	"context"
	"flag"
	"log"
	"os/signal"
	"syscall"

	"github.com/cjmustard/console-connect/broadcaster"
)

func main() {
	optionsPath := flag.String("config", "", "optional path to broadcaster options JSON")
	listenAddr := flag.String("listen", "", "override listener address for bedrock clients")
	flag.Parse()

	opts := broadcaster.Options{}
	if optionsPath != nil && *optionsPath != "" {
		loaded, err := broadcaster.LoadOptions(*optionsPath)
		if err != nil {
			log.Fatalf("load options: %v", err)
		}
		opts = loaded
	}
	opts.ApplyDefaults()
	if listenAddr != nil && *listenAddr != "" {
		opts.Listener.Address = *listenAddr
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	svc, err := broadcaster.New(opts)
	if err != nil {
		log.Fatalf("initialise broadcaster: %v", err)
	}

	if err := svc.Run(ctx); err != nil {
		log.Fatalf("broadcaster stopped: %v", err)
	}
}
