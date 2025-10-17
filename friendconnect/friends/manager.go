package friends

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/cjmustard/friend-connect/friendconnect/account"
)

type Friend struct {
	XUID      string    `json:"xuid"`
	Gamertag  string    `json:"gamertag"`
	Added     time.Time `json:"added"`
	Online    bool      `json:"online"`
	Following bool      `json:"following"`
	Followed  bool      `json:"followed"`
}

type Provider interface {
	ListFriends(ctx context.Context, acct *account.Account) ([]Friend, error)
	AddFriend(ctx context.Context, acct *account.Account, gamertag string) error
	AddFriendByXUID(ctx context.Context, acct *account.Account, xuid, gamertag string) error
	RemoveFriend(ctx context.Context, acct *account.Account, gamertag string) error
	PendingRequests(ctx context.Context, acct *account.Account) ([]Request, error)
	AcceptRequests(ctx context.Context, acct *account.Account, xuids []string) ([]Request, error)
}

type Options struct {
	AutoAccept bool
	AutoAdd    bool
	SyncEvery  time.Duration
}

type Request struct {
	XUID     string
	Gamertag string
}

type Manager struct {
	log      *slog.Logger
	accounts *account.Store
	provider Provider
	friends  map[string][]Friend
	mu       sync.RWMutex
	opts     Options
}

func NewManager(log *slog.Logger, accounts *account.Store, provider Provider) *Manager {
	if provider == nil {
		provider = NewXboxProvider(nil)
	}
	return &Manager{log: log, accounts: accounts, provider: provider, friends: map[string][]Friend{}}
}

func (m *Manager) Configure(opts Options) {
	if opts.SyncEvery <= 0 {
		opts.SyncEvery = time.Minute
	}
	m.opts = opts
}

func (m *Manager) Run(ctx context.Context) {
	if m.opts.SyncEvery <= 0 {
		m.opts.SyncEvery = time.Minute
	}

	ticker := time.NewTicker(m.opts.SyncEvery)
	defer ticker.Stop()

	m.syncAndProcess(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.syncAndProcess(ctx)
		}
	}
}

func (m *Manager) syncAndProcess(ctx context.Context) {
	if err := m.Sync(ctx); err != nil {
		m.log.Error("friend sync", slog.Any("error", err))
	}

	if m.opts.AutoAdd {
		m.autoFollowBack(ctx)
	}

	if m.opts.AutoAccept {
		m.acceptPending(ctx)
	}
}

func (m *Manager) Sync(ctx context.Context) error {
	var wg sync.WaitGroup
	var firstErr error
	var once sync.Once

	m.accounts.WithAccounts(func(acct *account.Account) {
		wg.Add(1)
		go func(ac *account.Account) {
			defer wg.Done()
			friends, err := m.provider.ListFriends(ctx, ac)
			if err != nil {
				m.log.Error("list friends", slog.String("gamertag", ac.Gamertag()), slog.Any("error", err))
				once.Do(func() { firstErr = err })
				return
			}

			m.mu.Lock()
			m.friends[ac.Gamertag()] = friends
			m.mu.Unlock()
		}(acct)
	})

	wg.Wait()
	return firstErr
}

func (m *Manager) autoFollowBack(ctx context.Context) {
	m.accounts.WithAccounts(func(acct *account.Account) {
		tag := acct.Gamertag()
		friends := m.Friends(tag)
		for _, fr := range friends {
			if fr.XUID == "" {
				continue
			}
			if fr.Following && !fr.Followed {
				if err := m.provider.AddFriendByXUID(ctx, acct, fr.XUID, fr.Gamertag); err != nil {
					m.log.Error("auto follow", slog.String("from", tag), slog.String("to", fr.Gamertag), slog.Any("error", err))
				} else {
					m.log.Info("followed back", slog.String("gamertag", fr.Gamertag), slog.String("xuid", fr.XUID))
				}
			}
		}
	})
}

func (m *Manager) acceptPending(ctx context.Context) {
	m.accounts.WithAccounts(func(acct *account.Account) {
		requests, err := m.provider.PendingRequests(ctx, acct)
		if err != nil {
			m.log.Error("fetch friend requests", slog.String("gamertag", acct.Gamertag()), slog.Any("error", err))
			return
		}
		if len(requests) == 0 {
			return
		}
		xuids := make([]string, 0, len(requests))
		for _, r := range requests {
			xuids = append(xuids, r.XUID)
		}
		accepted, err := m.provider.AcceptRequests(ctx, acct, xuids)
		if err != nil {
			m.log.Error("accept friend requests", slog.String("gamertag", acct.Gamertag()), slog.Any("error", err))
			return
		}
		if len(accepted) == 0 {
			accepted = requests
		}
		for _, r := range accepted {
			name := r.Gamertag
			if name == "" {
				name = r.XUID
			}
			m.log.Info("accepted friend request", slog.String("from", name))
		}
	})
}

func (m *Manager) AutoAdd(ctx context.Context, gamertag string) error {
	if gamertag == "" {
		return errors.New("missing gamertag")
	}
	m.accounts.WithAccounts(func(acct *account.Account) {
		if err := m.provider.AddFriend(ctx, acct, gamertag); err != nil {
			m.log.Error("auto add friend", slog.String("gamertag", gamertag), slog.String("account", acct.Gamertag()), slog.Any("error", err))
		}
	})
	return nil
}

func (m *Manager) Snapshot() map[string][]Friend {
	m.mu.RLock()
	defer m.mu.RUnlock()
	copy := make(map[string][]Friend, len(m.friends))
	for k, v := range m.friends {
		friends := make([]Friend, len(v))
		copySlice(friends, v)
		copy[k] = friends
	}
	return copy
}

func (m *Manager) Friends(gamertag string) []Friend {
	m.mu.RLock()
	defer m.mu.RUnlock()
	friends := m.friends[gamertag]
	out := make([]Friend, len(friends))
	copySlice(out, friends)
	return out
}

func copySlice(dst, src []Friend) {
	for i := range src {
		dst[i] = src[i]
	}
}
