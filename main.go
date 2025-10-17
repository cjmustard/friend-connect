package main

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"time"

	"github.com/cjmustard/consoleconnect/broadcast"
	"github.com/sandertv/gophertunnel/minecraft/auth"
	"golang.org/x/oauth2"
)

const tokenFile = "assets/token.tok"

func main() {
	refresh := ensureRefreshToken()

	opts := broadcast.Options{
		Accounts: []broadcast.AccountOptions{
			{
				Gamertag:     "CJMustard1452",
				RefreshToken: refresh,
				ShowAsOnline: true,
				PreferredIPs: []string{"0.0.0.0"},
			},
		},
		Friends: broadcast.FriendOptions{
			AutoAccept: true,
			AutoAdd:    true,
			SyncTicker: time.Minute,
		},
		Listener: broadcast.ListenerOptions{
			Address: "0.0.0.0:19132",
			Name:    "Console Connect",
			Message: "Minecraft Presence Relay",
		},
		Relay: broadcast.RelayOptions{
			RemoteAddress: "127.0.0.1:19132",
			VerifyTarget:  true,
			Timeout:       5 * time.Second,
		},
	}

	svc, err := broadcast.New(opts)
	if err != nil {
		log.Fatalf("build broadcaster: %v", err)
	}

	if err := svc.Run(context.Background()); err != nil {
		log.Fatalf("broadcaster stopped: %v", err)
	}
}

func ensureRefreshToken() string {
	src := tokenSource()
	tok, err := src.Token()
	if err != nil {
		log.Fatalf("obtain refresh token: %v", err)
	}
	if tok.RefreshToken == "" {
		log.Fatal("received empty refresh token")
	}
	return tok.RefreshToken
}

func tokenSource() oauth2.TokenSource {
	if err := os.MkdirAll("assets", 0o755); err != nil {
		log.Fatalf("prepare token cache: %v", err)
	}

	token := new(oauth2.Token)
	if data, err := os.ReadFile(tokenFile); err == nil {
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
		if writeErr := os.WriteFile(tokenFile, data, 0o644); writeErr != nil {
			log.Printf("warning: failed to persist token cache: %v", writeErr)
		}
	}

	return oauth2.ReuseTokenSource(tok, src)
}
