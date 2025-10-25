package session

import (
	"context"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/df-mc/go-xsapi/mpsd"
	"github.com/sandertv/gophertunnel/minecraft"
	"github.com/sandertv/gophertunnel/minecraft/room"

	"github.com/cjmustard/friend-connect/friendconnect/xbox"
)

const (
	httpClientTimeout      = 10 * time.Second
	relayTimeout           = 5 * time.Second
	presenceRetryInterval  = time.Minute
	sessionRefreshInterval = 5 * time.Minute
	transferWaitTimeout    = 2 * time.Second
)

type Server struct {
	log      *log.Logger
	accounts *xbox.Store
	listener *minecraft.Listener

	conns           map[string]*minecraft.Conn
	announcers      map[string]*room.XBLAnnouncer
	sessions        map[string]*mpsd.Session
	startedAccounts map[string]struct{}
	netherAccounts  map[string]struct{}

	httpClient     *http.Client
	nether         *SignalingHub
	netherProvider minecraft.ServerStatusProvider

	listenPort uint16
	listenGUID string
	netherCtx  context.Context

	relay      RelayOptions
	viewership ViewershipOptions

	ctx context.Context

	mu sync.RWMutex
}

type Options struct {
	Addr     string
	Provider minecraft.ServerStatusProvider
}

type RelayOptions struct {
	RemoteAddress string
	Timeout       time.Duration
}

// ViewershipOptions defines how the session appears in Xbox Live and server browsers.
// These settings control the visibility, accessibility, and display information
// for the Minecraft session that will be broadcast to friends and other players.
type ViewershipOptions struct {
	// Joinability controls who can join the session (friends only, public, etc.)
	Joinability string
	// MaxMemberCount is the maximum number of players allowed to join the session
	MaxMemberCount int
	// MemberCount is the current number of players in the session
	MemberCount int
	// BroadcastSetting determines how visible the session is to others
	BroadcastSetting int32
	// WorldType is the game mode displayed to players (Survival, Creative, etc.)
	WorldType string
	// WorldName is the name of the world/server that will be displayed
	WorldName string
	// HostName is the name of the session host shown to other players
	HostName string
	// LanGame indicates whether this session is restricted to local network only
	LanGame bool
	// OnlineCrossPlatformGame enables cross-platform play between PC, mobile, and console
	OnlineCrossPlatformGame bool
	// CrossPlayDisabled disables cross-play functionality between different platforms
	CrossPlayDisabled bool
}

// NewServer creates a new Minecraft server instance with the provided dependencies.
// The server handles Xbox Live session announcements and client connections.
func NewServer(logger *log.Logger, accounts *xbox.Store, netherHub *SignalingHub, httpClient *http.Client) *Server {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: httpClientTimeout}
	}
	if logger == nil {
		logger = log.New(os.Stdout, "", 0)
	}
	return &Server{
		log:             logger,
		accounts:        accounts,
		conns:           map[string]*minecraft.Conn{},
		httpClient:      httpClient,
		nether:          netherHub,
		announcers:      map[string]*room.XBLAnnouncer{},
		sessions:        map[string]*mpsd.Session{},
		startedAccounts: map[string]struct{}{},
		netherAccounts:  map[string]struct{}{},
		viewership: ViewershipOptions{
			Joinability:             room.JoinabilityJoinableByFriends,
			MaxMemberCount:          8,
			MemberCount:             1,
			BroadcastSetting:        room.BroadcastSettingFriendsOfFriends,
			WorldType:               "Survival",
			WorldName:               "",
			HostName:                "",
			LanGame:                 false,
			OnlineCrossPlatformGame: true,
			CrossPlayDisabled:       false,
		},
	}
}

// ConfigureRelay sets up the relay configuration for transferring clients to remote servers.
func (m *Server) ConfigureRelay(opts RelayOptions) {
	if opts.Timeout <= 0 {
		opts.Timeout = relayTimeout
	}
	m.relay = opts
}

// ConfigureViewership sets up the viewership options for session announcements.
func (m *Server) ConfigureViewership(opts ViewershipOptions) {
	if opts.MaxMemberCount <= 0 {
		opts.MaxMemberCount = 8
	}
	if opts.MemberCount <= 0 {
		opts.MemberCount = 1
	}
	if opts.WorldType == "" {
		opts.WorldType = "Survival"
	}
	if opts.Joinability == "" {
		opts.Joinability = room.JoinabilityJoinableByFriends
	}
	if opts.BroadcastSetting == 0 {
		opts.BroadcastSetting = room.BroadcastSettingFriendsOfFriends
	}
	m.viewership = opts
}

func (m *Server) Start(ctx context.Context) {
	if ctx == nil {
		ctx = context.Background()
	}
	m.setContext(ctx)
	m.accounts.WithAccounts(func(acct *xbox.Account) {
		m.startAccount(acct)
	})
	go m.refreshSessions(ctx)
}

func (m *Server) setContext(ctx context.Context) {
	m.mu.Lock()
	m.ctx = ctx
	m.mu.Unlock()
}

func (m *Server) sessionContext() context.Context {
	m.mu.RLock()
	ctx := m.ctx
	m.mu.RUnlock()
	if ctx == nil {
		return context.Background()
	}
	return ctx
}

func (m *Server) startAccount(acct *xbox.Account) {
	if acct == nil {
		return
	}
	id := acct.SessionID()
	m.mu.Lock()
	if _, ok := m.startedAccounts[id]; ok {
		m.mu.Unlock()
		return
	}
	m.startedAccounts[id] = struct{}{}
	m.mu.Unlock()

	ctx := m.sessionContext()
	go func() {
		if err := m.ensureSession(ctx, acct); err != nil {
			m.log.Printf("create session failed for %s: %v", acct.Gamertag(), err)
		}
	}()
	go m.runPresence(ctx, acct)
}

func (m *Server) AttachAccount(ctx context.Context, acct *xbox.Account) {
	if acct == nil {
		return
	}
	if ctx != nil {
		m.setContext(ctx)
	}
	m.startAccount(acct)
	provider, providerCtx := m.netherRuntime()
	if provider != nil && m.nether != nil {
		if providerCtx == nil {
			providerCtx = m.sessionContext()
		}
		m.startNetherForAccount(providerCtx, provider, acct)
	}
}

func (m *Server) setNetherRuntime(ctx context.Context, provider minecraft.ServerStatusProvider) {
	m.mu.Lock()
	m.netherCtx = ctx
	m.netherProvider = provider
	m.mu.Unlock()
}

func (m *Server) netherRuntime() (minecraft.ServerStatusProvider, context.Context) {
	m.mu.RLock()
	provider := m.netherProvider
	ctx := m.netherCtx
	m.mu.RUnlock()
	return provider, ctx
}

func (m *Server) startNetherForAccount(ctx context.Context, provider minecraft.ServerStatusProvider, acct *xbox.Account) {
	if acct == nil || provider == nil || m.nether == nil {
		return
	}
	if ctx == nil {
		ctx = m.sessionContext()
	}
	id := acct.SessionID()
	m.mu.Lock()
	if _, ok := m.netherAccounts[id]; ok {
		m.mu.Unlock()
		return
	}
	m.netherAccounts[id] = struct{}{}
	m.mu.Unlock()
	go m.listenNetherForAccount(ctx, provider, acct)
}
