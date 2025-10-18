package main

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/cjmustard/friend-connect/friendconnect"
	"github.com/sandertv/gophertunnel/minecraft/auth"
	"golang.org/x/oauth2"
)

const (
	tokenFile       = "assets/token.tok"
	listenerAddress = "0.0.0.0:19132"
	listenerName    = "Console Connect"
	listenerMessage = "Minecraft Presence Relay"
	relayTimeout    = 5 * time.Second
)

func main() {
	token := ensureToken(tokenFile)

	logger := log.New(os.Stdout, "", 0)

	// Suppress external library warnings by redirecting standard log to discard
	log.SetOutput(io.Discard)

	opts := friendconnect.Options{
		Tokens: []*oauth2.Token{token},
		Friends: friendconnect.FriendOptions{
			AutoAccept: true,
			AutoAdd:    true,
			SyncTicker: time.Second * 10,
		},
		Listener: friendconnect.ListenerOptions{
			Address: listenerAddress,
			Name:    listenerName,
			Message: listenerMessage,
		},
		Relay: friendconnect.RelayOptions{
			RemoteAddress: "zeqa.net:19132",
			VerifyTarget:  false,
			Timeout:       relayTimeout,
		},
		Logger: logger,
	}

	svc, err := friendconnect.New(opts)
	if err != nil {
		log.Fatalf("build friendconnect: %v", err)
	}

	logger.Println("friendconnect started")
	if err := svc.Run(context.Background()); err != nil {
		log.Fatalf("friendconnect stopped: %v", err)
	}
}

func ensureToken(tokenPath string) *oauth2.Token {
	src := tokenSource(tokenPath)
	tok, err := src.Token()
	if err != nil {
		log.Fatalf("obtain refresh token: %v", err)
	}
	if tok.RefreshToken == "" {
		log.Fatal("received empty refresh token")
	}
	clone := *tok
	return &clone
}

func tokenSource(tokenPath string) oauth2.TokenSource {
	dir := filepath.Dir(tokenPath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		log.Fatalf("prepare token cache: %v", err)
	}

	token := new(oauth2.Token)
	if data, err := os.ReadFile(tokenPath); err == nil {
		_ = json.Unmarshal(data, token)
	} else {
		fresh, reqErr := auth.RequestLiveToken()
		if reqErr != nil {
			log.Fatalf("device auth: %v", reqErr)
		}
		token = fresh
	}

	src := auth.RefreshTokenSource(token)
	tok, err := src.Token()
	if err != nil {
		fresh, reqErr := auth.RequestLiveToken()
		if reqErr != nil {
			log.Fatalf("renew device auth: %v", reqErr)
		}
		src = auth.RefreshTokenSource(fresh)
		tok, err = src.Token()
		if err != nil {
			log.Fatalf("refresh token from source: %v", err)
		}
	}

	if data, err := json.Marshal(tok); err == nil {
		if writeErr := os.WriteFile(tokenPath, data, 0o644); writeErr != nil {
			log.Printf("warning: failed to persist token cache: %v", writeErr)
		}
	}

	return oauth2.ReuseTokenSource(tok, src)
}
