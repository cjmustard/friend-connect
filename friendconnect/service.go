package friendconnect

import (
	"context"
	"fmt"
	"log"
	"os"
	"sync/atomic"
	"time"

	"github.com/sandertv/gophertunnel/minecraft"
	"golang.org/x/oauth2"

	"github.com/cjmustard/friend-connect/friendconnect/friends"
	"github.com/cjmustard/friend-connect/friendconnect/session"
	"github.com/cjmustard/friend-connect/friendconnect/xbox"
)

const (
	initialRestartDelay = time.Second
	maxRestartDelay     = 30 * time.Second
)

type Service struct {
	opts     Options
	log      *log.Logger
	accounts *xbox.Store
	fhandler *friends.Handler
	server   *session.Server
	nether   *session.SignalingHub

	started int32
}

// NewWithOptions creates a new FriendConnect service with the provided options.
func NewWithOptions(ctx context.Context, opts Options) (*Service, error) {
	opts.ApplyDefaults()

	loggr := opts.Logger
	if loggr == nil {
		loggr = log.New(os.Stdout, "", 0)
	}
	acctStore := xbox.NewStore()
	for _, tok := range opts.Tokens {
		if _, err := acctStore.Register(ctx, tok); err != nil {
			return nil, fmt.Errorf("register account: %w", err)
		}
	}

	httpClient := opts.HTTPClient

	provider := friends.NewXboxProvider(httpClient)
	handler := friends.NewHandler(loggr, acctStore, provider)
	handler.Configure(friends.Options{
		AutoAccept: opts.Friends.AutoAccept,
		AutoAdd:    opts.Friends.AutoAdd,
		SyncEvery:  opts.Friends.SyncTicker,
	})

	netherHub := session.NewSignalingHub(loggr, acctStore)

	server := session.NewServer(loggr, acctStore, netherHub, httpClient)
	server.ConfigureRelay(session.RelayOptions{
		RemoteAddress: opts.Relay.RemoteAddress,
		Timeout:       opts.Relay.Timeout,
	})
	server.ConfigureViewership(opts.Viewership)

	srv := &Service{
		opts:     opts,
		log:      loggr,
		accounts: acctStore,
		fhandler: handler,
		server:   server,
		nether:   netherHub,
	}

	return srv, nil
}

// New creates a new FriendConnect service with sensible defaults.
func New(ctx context.Context, domain string, tokens ...*oauth2.Token) (*Service, error) {
	opts := Options{
		Tokens: tokens,
		Friends: FriendOptions{
			AutoAccept: true,
			AutoAdd:    true,
			SyncTicker: 20 * time.Second,
		},
		Listener: ListenerOptions{
			Address: "0.0.0.0:19132",
			Name:    "Friend Connect",
			Message: "Minecraft Presence Relay",
		},
		Relay: RelayOptions{
			RemoteAddress: domain,
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
	return NewWithOptions(ctx, opts)
}

// Run starts the FriendConnect service and begins listening for connections.
func (s *Service) Run(ctx context.Context) error {
	if !atomic.CompareAndSwapInt32(&s.started, 0, 1) {
		return fmt.Errorf("service already started")
	}

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
	s.server.Start(ctx)

	go s.fhandler.Run(ctx)

	return s.listenAndRestart(ctx, listenerProvider)
}

func (s *Service) listenAndRestart(ctx context.Context, listenerProvider minecraft.ServerStatusProvider) error {
	restartDelay := initialRestartDelay

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		err := s.server.Listen(ctx, session.Options{Addr: s.opts.Listener.Address, Provider: listenerProvider})
		if err == nil || ctx.Err() != nil {
			return ctx.Err()
		}

		s.log.Printf("server stopped with error: %v, restarting in %v", err, restartDelay)

		if s.server != nil {
			s.server.Reset()
		}
		if s.nether != nil {
			s.nether.Reset()
			s.nether.Start(ctx)
		}
		if s.server != nil {
			s.server.Start(ctx)
		}
		go s.fhandler.Run(ctx)

		s.log.Printf("service components reinitialized")

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(restartDelay):
			restartDelay *= 2
			if restartDelay > maxRestartDelay {
				restartDelay = maxRestartDelay
			}
		}
	}
}
