package friendconnect

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/sandertv/gophertunnel/minecraft"
	"golang.org/x/oauth2"

	"github.com/cjmustard/friend-connect/friendconnect/friends"
	"github.com/cjmustard/friend-connect/friendconnect/session"
	"github.com/cjmustard/friend-connect/friendconnect/xbox"
)

type Service struct {
	opts     Options
	log      *log.Logger
	accounts *xbox.Store
	friends  *friends.Manager
	sessions *session.Server
	nether   *session.SignalingHub

	started bool
	mu      sync.RWMutex
}

// NewWithOptions creates a new FriendConnect service with the provided options.
func NewWithOptions(opts Options) (*Service, error) {
	opts.ApplyDefaults()

	loggr := opts.Logger
	if loggr == nil {
		loggr = log.New(os.Stdout, "", 0)
	}
	acctStore := xbox.NewStore()
	for _, tok := range opts.Tokens {
		if _, err := acctStore.Register(context.Background(), tok); err != nil {
			return nil, fmt.Errorf("register account: %w", err)
		}
	}

	httpClient := &http.Client{Timeout: 10 * time.Second}

	provider := friends.NewXboxProvider(httpClient)
	friendMgr := friends.NewManager(loggr, acctStore, provider)
	friendMgr.Configure(friends.Options{
		AutoAccept: opts.Friends.AutoAccept,
		AutoAdd:    opts.Friends.AutoAdd,
		SyncEvery:  opts.Friends.SyncTicker,
	})

	netherHub := session.NewSignalingHub(loggr, acctStore)

	sessionMgr := session.NewServer(loggr, acctStore, netherHub, httpClient)
	sessionMgr.ConfigureRelay(session.RelayOptions{
		RemoteAddress: opts.Relay.RemoteAddress,
		VerifyTarget:  opts.Relay.VerifyTarget,
		Timeout:       opts.Relay.Timeout,
	})
	sessionMgr.ConfigureViewership(opts.Viewership)

	srv := &Service{
		opts:     opts,
		log:      loggr,
		accounts: acctStore,
		friends:  friendMgr,
		sessions: sessionMgr,
		nether:   netherHub,
	}

	return srv, nil
}

// New creates a new FriendConnect service with sensible defaults.
func New(domain string, tokens ...*oauth2.Token) (*Service, error) {
	opts := Options{
		Tokens: tokens,
		Friends: FriendOptions{
			AutoAccept: true,
			AutoAdd:    true,
			SyncTicker: time.Minute,
		},
		Listener: ListenerOptions{
			Address: "0.0.0.0:19132",
			Name:    "Friend Connect",
			Message: "Minecraft Presence Relay",
		},
		Relay: RelayOptions{
			RemoteAddress: domain,
			VerifyTarget:  false,
			Timeout:       5 * time.Second,
		},
		Viewership: session.ViewershipOptions{
			MaxMemberCount:          8,
			WorldType:               "Survival",
			WorldName:               "",
			HostName:                "",
			Joinability:             "JoinableByFriends",
			BroadcastSetting:        3,
			LanGame:                 false,
			OnlineCrossPlatformGame: true,
			CrossPlayDisabled:       false,
		},
		Logger: nil,
	}
	return NewWithOptions(opts)
}

// Run starts the FriendConnect service and begins listening for connections.
func (s *Service) Run(ctx context.Context) error {
	s.mu.Lock()
	if s.started {
		s.mu.Unlock()
		return fmt.Errorf("service already started")
	}
	s.started = true
	s.mu.Unlock()

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var listenerProvider minecraft.ServerStatusProvider = minecraft.NewStatusProvider(s.opts.Listener.Name, s.opts.Listener.Message)
	if addr := s.opts.Relay.RemoteAddress; addr != "" {
		if foreign, err := minecraft.NewForeignStatusProvider(addr); err == nil {
			listenerProvider = foreign
		} else {
			s.log.Printf("relay status provider unavailable: %s - %v", addr, err)
		}
	}

	s.nether.Start(ctx)
	s.sessions.Start(ctx)

	go s.friends.Run(ctx)

	return s.sessions.Listen(ctx, session.Options{Addr: s.opts.Listener.Address, Provider: listenerProvider})
}
