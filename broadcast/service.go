package broadcast

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/sandertv/gophertunnel/minecraft"
	"golang.org/x/oauth2"

	"github.com/cjmustard/consoleconnect/broadcast/account"
	"github.com/cjmustard/consoleconnect/broadcast/friends"
	"github.com/cjmustard/consoleconnect/broadcast/logger"
	"github.com/cjmustard/consoleconnect/broadcast/nether"
	"github.com/cjmustard/consoleconnect/broadcast/session"
)

type Service struct {
	opts     Options
	log      *logger.Logger
	accounts *account.Store
	friends  *friends.Manager
	sessions *session.Server
	nether   *nether.SignalingHub

	started bool
	mu      sync.RWMutex
}

func New(opts Options) (*Service, error) {
	opts.ApplyDefaults()

	loggr := opts.Logger
	if loggr == nil {
		loggr = logger.New()
	}
	acctStore := account.NewStore()
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

	netherHub := nether.NewHub(loggr, acctStore)

	sessionMgr := session.NewServer(loggr, acctStore, netherHub, httpClient)
	sessionMgr.ConfigureRelay(session.RelayOptions{
		RemoteAddress: opts.Relay.RemoteAddress,
		VerifyTarget:  opts.Relay.VerifyTarget,
		Timeout:       opts.Relay.Timeout,
	})

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

func (s *Service) Options() Options {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.opts
}

func (s *Service) AddToken(ctx context.Context, tok *oauth2.Token) (*account.Account, error) {
	if s.accounts == nil {
		return nil, fmt.Errorf("account store unavailable")
	}
	acct, err := s.accounts.Register(ctx, tok)
	if err != nil {
		return nil, fmt.Errorf("register account: %w", err)
	}

	s.mu.RLock()
	started := s.started
	s.mu.RUnlock()
	if started {
		if s.nether != nil {
			s.nether.AttachAccount(acct)
		}
		if s.sessions != nil {
			s.sessions.AttachAccount(ctx, acct)
		}
	}
	return acct, nil
}

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
			s.log.Warnf("relay status provider for %s unavailable: %v", addr, err)
		}
	}

	s.nether.Start(ctx)
	s.sessions.Start(ctx)

	go s.friends.Run(ctx)

	return s.sessions.Listen(ctx, session.Options{Addr: s.opts.Listener.Address, Provider: listenerProvider})
}

var _ OptionsProvider = (*Service)(nil)
