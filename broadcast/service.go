package broadcast

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/sandertv/gophertunnel/minecraft"

	"github.com/cjmustard/consoleconnect/broadcast/account"
	"github.com/cjmustard/consoleconnect/broadcast/friends"
	"github.com/cjmustard/consoleconnect/broadcast/logger"
	"github.com/cjmustard/consoleconnect/broadcast/nether"
	"github.com/cjmustard/consoleconnect/broadcast/session"
)

type Service struct {
	opts     Options
	log      *logger.Logger
	accounts *account.Manager
	friends  *friends.Manager
	sessions *session.Manager
	nether   *nether.Manager

	started bool
	mu      sync.RWMutex
}

func New(opts Options) (*Service, error) {
	opts.ApplyDefaults()

	loggr := logger.New()
	acctMgr := account.NewManager()
	for _, acct := range opts.Accounts {
		if _, err := acctMgr.Register(context.Background(), account.Options{
			Gamertag:     acct.Gamertag,
			RefreshToken: acct.RefreshToken,
			ShowAsOnline: acct.ShowAsOnline,
		}); err != nil {
			return nil, fmt.Errorf("register account %s: %w", acct.Gamertag, err)
		}
	}

	httpClient := &http.Client{Timeout: 10 * time.Second}

	provider := friends.NewXboxProvider(httpClient)
	friendMgr := friends.NewManager(loggr, acctMgr, provider)
	friendMgr.Configure(friends.Options{
		AutoAccept: opts.Friends.AutoAccept,
		AutoAdd:    opts.Friends.AutoAdd,
		SyncEvery:  opts.Friends.SyncTicker,
	})

	netherMgr := nether.NewManager(loggr, acctMgr)

	sessionMgr := session.NewManager(loggr, acctMgr, netherMgr, httpClient)
	sessionMgr.ConfigureRelay(session.RelayOptions{
		RemoteAddress: opts.Relay.RemoteAddress,
		VerifyTarget:  opts.Relay.VerifyTarget,
		Timeout:       opts.Relay.Timeout,
	})

	srv := &Service{
		opts:     opts,
		log:      loggr,
		accounts: acctMgr,
		friends:  friendMgr,
		sessions: sessionMgr,
		nether:   netherMgr,
	}

	return srv, nil
}

func (s *Service) Options() Options {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.opts
}

func (s *Service) AddAccount(ctx context.Context, opts AccountOptions) (*account.Account, error) {
	if s.accounts == nil {
		return nil, fmt.Errorf("account manager unavailable")
	}
	acct, err := s.accounts.Register(ctx, account.Options{
		Gamertag:     opts.Gamertag,
		RefreshToken: opts.RefreshToken,
		ShowAsOnline: opts.ShowAsOnline,
	})
	if err != nil {
		return nil, fmt.Errorf("register account %s: %w", opts.Gamertag, err)
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
