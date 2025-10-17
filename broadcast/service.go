package broadcast

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/sandertv/gophertunnel/minecraft"

	"github.com/cjmustard/consoleconnect/broadcast/account"
	"github.com/cjmustard/consoleconnect/broadcast/friends"
	"github.com/cjmustard/consoleconnect/broadcast/gallery"
	"github.com/cjmustard/consoleconnect/broadcast/logger"
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
		if _, err := acctMgr.Register(context.Background(), acct.Gamertag, acct.RefreshToken); err != nil {
			return nil, fmt.Errorf("register account %s: %w", acct.Gamertag, err)
		}
	}

	store, err := storage.NewManager(opts.Storage.Directory, opts.Gallery.Path)
	if err != nil {
		return nil, fmt.Errorf("storage: %w", err)
	}

	provider := friends.NewStoredProvider(store.Backend())
	notify := notifications.NewManager(loggr, opts.Notifications)
	friendMgr := friends.NewManager(loggr, acctMgr, provider, notify)

	galleryMgr, err := gallery.New(opts.Gallery.Path)
	if err != nil {
		return nil, fmt.Errorf("gallery: %w", err)
	}

	sessionMgr := session.NewManager(loggr, acctMgr)

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

	go func() {
		if s.pinger != nil {
			s.pinger.Run(ctx)
		}
	}()

	go func() {
		ticker := time.NewTicker(s.opts.Friends.SyncTicker)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := s.friends.Sync(ctx); err != nil {
					s.log.Errorf("friend sync: %v", err)
				}
			}
		}
	}()

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
