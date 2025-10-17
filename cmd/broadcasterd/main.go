package main

import (
	"context"
	"flag"
	"log"
	"os/signal"
	"syscall"
	"time"

	"github.com/sandertv/gophertunnel/minecraft"

	"github.com/cjmustard/console-connect/internal/broadcaster/account"
	"github.com/cjmustard/console-connect/internal/broadcaster/config"
	"github.com/cjmustard/console-connect/internal/broadcaster/friends"
	"github.com/cjmustard/console-connect/internal/broadcaster/gallery"
	"github.com/cjmustard/console-connect/internal/broadcaster/logger"
	"github.com/cjmustard/console-connect/internal/broadcaster/notifications"
	"github.com/cjmustard/console-connect/internal/broadcaster/ping"
	"github.com/cjmustard/console-connect/internal/broadcaster/session"
	"github.com/cjmustard/console-connect/internal/broadcaster/storage"
	"github.com/cjmustard/console-connect/internal/broadcaster/web"
)

func main() {
	configPath := flag.String("config", "config.json", "path to configuration file")
	bindAddr := flag.String("bind", "0.0.0.0:19132", "listener address for bedrock clients")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	loggr := logger.New()

	acctManager := account.NewManager()
	for _, acct := range cfg.Accounts {
		if _, err := acctManager.Register(ctx, acct.Gamertag, acct.RefreshToken); err != nil {
			log.Fatalf("register account %s: %v", acct.Gamertag, err)
		}
	}

	store, err := storage.NewManager(cfg.Storage.Directory, cfg.Gallery.Path)
	if err != nil {
		log.Fatalf("storage: %v", err)
	}

	friendProvider := friends.NewStoredProvider(store.Backend())
	notify := notifications.NewManager(loggr, cfg.Notifications)
	friendManager := friends.NewManager(loggr, acctManager, friendProvider, notify)

	galleryManager, err := gallery.New(cfg.Gallery.Path)
	if err != nil {
		log.Fatalf("gallery: %v", err)
	}

	sessionManager := session.NewManager(loggr, acctManager)

	listenerProvider := minecraft.NewStatusProvider("Broadcaster", "Minecraft Presence Relay")
	go func() {
		if err := sessionManager.Listen(ctx, session.Options{Addr: *bindAddr, Provider: listenerProvider}); err != nil {
			log.Fatalf("session listener: %v", err)
		}
	}()

	if cfg.Ping.Enabled {
		pinger := ping.New(loggr, cfg.Ping.Target, cfg.Ping.Period)
		go pinger.Run(ctx)
	}

	go func() {
		ticker := time.NewTicker(cfg.FriendSettings.SyncTicker)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := friendManager.Sync(ctx); err != nil {
					loggr.Errorf("friend sync: %v", err)
				}
			}
		}
	}()

	webServer := web.NewServer(loggr, acctManager, sessionManager, friendManager, galleryManager)
	if err := webServer.ListenAndServe(ctx, cfg.HTTP); err != nil {
		log.Fatalf("web server: %v", err)
	}
}
