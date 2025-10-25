package friendconnect

import (
	"log"
	"net/http"
	"time"

	"golang.org/x/oauth2"

	"github.com/cjmustard/friend-connect/friendconnect/session"
	"github.com/sandertv/gophertunnel/minecraft/room"
)

// Options contains all configuration options for the FriendConnect service.
// It defines how the service behaves, connects to Xbox Live, manages friends,
// and presents the Minecraft session to other players.
type Options struct {
	// Tokens contains Xbox Live authentication tokens for connecting to Xbox services
	Tokens []*oauth2.Token
	// Friends defines how the service handles friend requests and synchronization
	Friends FriendOptions
	// Listener defines how the local server presents itself to connecting clients
	Listener ListenerOptions
	// Relay defines connection settings to the target Minecraft server
	Relay RelayOptions
	// Viewership controls how the session appears in Xbox Live and server browsers
	Viewership session.ViewershipOptions
	// HTTPClient is the HTTP client for making requests to Xbox Live services
	HTTPClient *http.Client
	// Logger is the logger instance for application logging and debugging output
	Logger *log.Logger
}

// FriendOptions controls friend management and synchronization behavior.
// These settings determine how the service handles friend requests and
// maintains the friend list with Xbox Live services.
type FriendOptions struct {
	// AutoAccept automatically accepts incoming friend requests without manual approval
	AutoAccept bool
	// AutoAdd automatically adds accepted friends to the current session
	AutoAdd bool
	// SyncTicker is the interval for synchronizing friend list with Xbox Live services
	SyncTicker time.Duration
}

// ListenerOptions defines how the local server presents itself to connecting clients.
// These settings control the server's network binding and display information
// shown to players when they connect.
type ListenerOptions struct {
	// Address is the network address and port where the local server will listen for connections
	Address string
	// Name is the server name displayed in Minecraft's server browser and friend lists
	Name string
	// Message is the server description shown to players when connecting
	Message string
}

// RelayOptions defines connection settings to the target Minecraft server.
// These settings control how the service connects to and relays traffic
// to the actual Minecraft server that players will join.
type RelayOptions struct {
	// RemoteAddress is the target Minecraft server address that connections will be relayed to
	RemoteAddress string
	// Timeout is the maximum time to wait when connecting to the target server
	Timeout time.Duration
}

// ApplyDefaults sets default values for any unset options.
func (o *Options) ApplyDefaults() {
	if o.Friends.SyncTicker <= 0 {
		o.Friends.SyncTicker = time.Minute
	}
	if o.Listener.Address == "" {
		o.Listener.Address = "0.0.0.0:19133"
	}
	if o.Listener.Name == "" {
		o.Listener.Name = "Friend Connect"
	}
	if o.Listener.Message == "" {
		o.Listener.Message = "Minecraft Presence Relay"
	}
	if o.Relay.Timeout <= 0 {
		o.Relay.Timeout = 5 * time.Second
	}
	if o.Viewership.MaxMemberCount <= 0 {
		o.Viewership.MaxMemberCount = 8
	}
	if o.Viewership.MemberCount <= 0 {
		o.Viewership.MemberCount = 1
	}
	if o.Viewership.WorldType == "" {
		o.Viewership.WorldType = "Survival"
	}
	if o.Viewership.Joinability == "" {
		o.Viewership.Joinability = room.JoinabilityJoinableByFriends
	}
	if o.Viewership.BroadcastSetting == 0 {
		o.Viewership.BroadcastSetting = room.BroadcastSettingFriendsOfFriends
	}
	if o.HTTPClient == nil {
		o.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}
}
