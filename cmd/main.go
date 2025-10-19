package main

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/oauth2"

	"github.com/cjmustard/friend-connect/friendconnect"
	"github.com/cjmustard/friend-connect/friendconnect/session"
	"github.com/sandertv/gophertunnel/minecraft/auth"
	"github.com/sandertv/gophertunnel/minecraft/room"
)

func main() {
	token := ensureToken("assets/token.tok")

	logger := log.New(os.Stdout, "", 0)

	hostName := envOrDefault("FRIENDCONNECT_HOST_NAME", "username")
	worldName := envOrDefault("FRIENDCONNECT_WORLD_NAME", "hostname")

	galleryImage := loadGalleryImage("assets/friend-connect.png", worldName, hostName)

	opts := friendconnect.Options{
		Tokens: []*oauth2.Token{token}, // Xbox Live authentication tokens for connecting to Xbox services
		Friends: friendconnect.FriendOptions{
			AutoAccept: true,             // Automatically accept incoming friend requests without manual approval
			AutoAdd:    true,             // Automatically add accepted friends to the current session
			SyncTicker: 10 * time.Second, // Interval for synchronizing friend list with Xbox Live services (XBL API rate limit is 30/min)
		},
		Listener: friendconnect.ListenerOptions{
			Address: "0.0.0.0:19132",            // Network address and port where the local server will listen for connections
			Name:    "Friend Connect",           // Server name displayed in Minecraft's server browser and friend lists
			Message: "Minecraft Presence Relay", // Server description shown to players when connecting
		},
		Relay: friendconnect.RelayOptions{
			RemoteAddress: "zeqa.net:19132", // Target Minecraft server address that connections will be relayed to
			VerifyTarget:  false,            // Whether to verify the target server is reachable before starting
			Timeout:       10 * time.Second, // Maximum time to wait when connecting to the target server
		},
		Viewership: session.ViewershipOptions{
			MaxMemberCount:          4,                                     // Maximum number of players allowed to join the session
			MemberCount:             1,                                     // Current number of players currently in the session
			WorldType:               "Survival",                            // Game mode type displayed to players (Survival, Creative, etc.)
			WorldName:               worldName,                             // Name of the world/server that will be displayed
			HostName:                hostName,                              // Name of the session host shown to other players
			Joinability:             room.JoinabilityJoinableByFriends,     // Access control for who can join (friends only, public, etc.)
			BroadcastSetting:        room.BroadcastSettingFriendsOfFriends, // Visibility level determining how the session appears to others
			LanGame:                 false,                                 // Whether this session is restricted to local network only
			OnlineCrossPlatformGame: true,                                  // Enable cross-platform play between PC, mobile, and console
			CrossPlayDisabled:       false,                                 // Disable cross-play functionality between different platforms
			Gallery: session.GalleryOptions{
				Title: worldName,
				Items: []session.GalleryImage{galleryImage},
			},
		},
		Logger: logger, // Logger instance for application logging and debugging output
	}

	svc, err := friendconnect.NewWithOptions(opts)
	if err != nil {
		log.Fatalf("build friendconnect: %v", err)
	}

	logger.Println("friendconnect started")
	if err := svc.Run(context.Background()); err != nil {
		log.Fatalf("friendconnect stopped: %v", err)
	}
}

// ensureToken loads an existing token from the given path, or prompts the user to authenticate
// if no token exists. Returns the OAuth2 token for Xbox Live authentication.
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

// tokenSource creates an OAuth2 token source for Xbox Live authentication.
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

func loadGalleryImage(path, worldName, hostName string) session.GalleryImage {
	data, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("load gallery image: %v", err)
	}
	return session.GalleryImage{
		Title:       worldName,
		Subtitle:    hostName,
		Data:        data,
		ContentType: session.GalleryContentTypePNG,
		ImageType:   session.GalleryImageTypeScreenshot,
	}
}

func envOrDefault(key, fallback string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return fallback
}
