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
	"github.com/cjmustard/consoleconnect/broadcast/gallery"
	"github.com/cjmustard/consoleconnect/broadcast/logger"
	"github.com/cjmustard/consoleconnect/broadcast/nether"
	"github.com/cjmustard/consoleconnect/broadcast/notifications"
	"github.com/cjmustard/consoleconnect/broadcast/ping"
	"github.com/cjmustard/consoleconnect/broadcast/session"
	"github.com/cjmustard/consoleconnect/broadcast/storage"
	"github.com/cjmustard/consoleconnect/broadcast/web"
)

type Service struct {
	opts          Options
	log           *logger.Logger
	accounts      *account.Manager
	friends       *friends.Manager
	gallery       *gallery.Manager
	storage       *storage.Manager
	sessions      *session.Manager
	nether        *nether.Manager
	notifications notifications.Manager
	pinger        *ping.Pinger
	webServer     *web.Server
	started       bool
	mu            sync.RWMutex
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
			PreferredIPs: acct.PreferredIPs,
		}); err != nil {
			return nil, fmt.Errorf("register account %s: %w", acct.Gamertag, err)
		}
	}

	store, err := storage.NewManager(opts.Storage.Directory, opts.Gallery.Path)
	if err != nil {
		return nil, fmt.Errorf("storage: %w", err)
	}

	httpClient := &http.Client{Timeout: 10 * time.Second}

	provider := friends.NewXboxProvider(httpClient)
	notify := notifications.NewManager(loggr, opts.Notifications)
	friendMgr := friends.NewManager(loggr, acctMgr, provider, notify)
	friendMgr.Configure(friends.Options{
		AutoAccept:    opts.Friends.AutoAccept,
		AutoAdd:       opts.Friends.AutoAdd,
		SyncEvery:     opts.Friends.SyncTicker,
		InviteEvery:   opts.Invite.Interval,
		InviteEnabled: opts.Invite.Enabled,
	})

	galleryMgr, err := gallery.New(opts.Gallery.Path)
	if err != nil {
		return nil, fmt.Errorf("gallery: %w", err)
	}

	netherMgr := nether.NewManager(loggr, acctMgr)

	sessionMgr := session.NewManager(loggr, acctMgr, netherMgr, httpClient)
	friendMgr.SetInviter(sessionMgr)

	var pinger *ping.Pinger
	if opts.Ping.Enabled {
		pinger = ping.New(loggr, opts.Ping.Target, opts.Ping.Period)
	}

	srv := &Service{
		opts:          opts,
		log:           loggr,
		accounts:      acctMgr,
		friends:       friendMgr,
		gallery:       galleryMgr,
		storage:       store,
		sessions:      sessionMgr,
		notifications: notify,
		pinger:        pinger,
		nether:        netherMgr,
	}

	srv.webServer = web.NewServer(loggr, acctMgr, sessionMgr, friendMgr, galleryMgr, srv.snapshotOptions)

	return srv, nil
}

func (s *Service) Options() Options {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.opts
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

	listenerProvider := minecraft.NewStatusProvider(s.opts.Listener.Name, s.opts.Listener.Message)

	s.nether.Start(ctx)
	s.sessions.Start(ctx)

	go func() {
		if s.pinger != nil {
			s.pinger.Run(ctx)
		}
	}()

	go s.friends.Run(ctx)

	go func() {
		if err := s.sessions.Listen(ctx, session.Options{Addr: s.opts.Listener.Address, Provider: listenerProvider}); err != nil {
			s.log.Errorf("session listener stopped: %v", err)
			cancel()
		}
	}()

	return s.webServer.ListenAndServe(ctx, web.HTTPOptions{
		Addr:         s.opts.HTTP.Addr,
		ReadTimeout:  s.opts.HTTP.ReadTimeout,
		WriteTimeout: s.opts.HTTP.WriteTimeout,
	})
}

var _ OptionsProvider = (*Service)(nil)

func (s *Service) snapshotOptions() any {
	return s.Options()
}
