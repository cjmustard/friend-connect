package friends

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/cjmustard/consoleconnect/broadcast/account"
	"github.com/cjmustard/consoleconnect/broadcast/logger"
	"github.com/cjmustard/consoleconnect/broadcast/notifications"
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
	SendInvite(ctx context.Context, acct *account.Account, sessionID, xuid string) error
}

type Options struct {
	AutoAccept    bool
	AutoAdd       bool
	SyncEvery     time.Duration
	InviteEvery   time.Duration
	InviteEnabled bool
}

type Request struct {
	XUID     string
	Gamertag string
}

type Manager struct {
	log        *logger.Logger
	accounts   *account.Manager
	provider   Provider
	friends    map[string][]Friend
	mu         sync.RWMutex
	notify     notifications.Manager
	opts       Options
	inviteMu   sync.Mutex
	lastInvite map[string]time.Time
}

func NewManager(log *logger.Logger, accounts *account.Manager, provider Provider, notify notifications.Manager) *Manager {
	if notify == nil {
		notify = notifications.NewManager(log, notifications.Config{})
	}
	if provider == nil {
		provider = NewXboxProvider(nil)
	}
	return &Manager{log: log, accounts: accounts, provider: provider, friends: map[string][]Friend{}, notify: notify, lastInvite: map[string]time.Time{}}
}

func (m *Manager) Configure(opts Options) {
	if opts.SyncEvery <= 0 {
		opts.SyncEvery = time.Minute
	}
	if opts.InviteEvery <= 0 {
		opts.InviteEvery = time.Minute
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
		m.log.Errorf("friend sync: %v", err)
	}

	if m.opts.AutoAdd {
		m.autoFollowBack(ctx)
	}

	if m.opts.AutoAccept {
		m.acceptPending(ctx)
	}

	if m.opts.InviteEnabled {
		m.inviteFriends(ctx)
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
				m.log.Errorf("list friends for %s: %v", ac.Gamertag(), err)
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
					m.log.Errorf("auto follow %s -> %s: %v", tag, fr.Gamertag, err)
				} else {
					m.log.Infof("followed back %s (%s)", fr.Gamertag, fr.XUID)
				}
			}
		}
	})
}

func (m *Manager) acceptPending(ctx context.Context) {
	m.accounts.WithAccounts(func(acct *account.Account) {
		requests, err := m.provider.PendingRequests(ctx, acct)
		if err != nil {
			m.log.Errorf("fetch friend requests for %s: %v", acct.Gamertag(), err)
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
			m.log.Errorf("accept friend requests for %s: %v", acct.Gamertag(), err)
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
			m.log.Infof("accepted friend request from %s", name)
			if m.opts.InviteEnabled {
				if err := m.provider.SendInvite(ctx, acct, acct.SessionID(), r.XUID); err != nil {
					m.log.Errorf("send invite to %s for %s: %v", name, acct.Gamertag(), err)
				} else {
					m.markInvited(acct.Gamertag(), r.XUID)
				}
			}
		}
	})
}

func (m *Manager) inviteFriends(ctx context.Context) {
	m.accounts.WithAccounts(func(acct *account.Account) {
		sessionID := acct.SessionID()
		if sessionID == "" {
			return
		}
		friends := m.Friends(acct.Gamertag())
		for _, fr := range friends {
			if fr.XUID == "" {
				continue
			}
			if !m.shouldInvite(acct.Gamertag(), fr.XUID) {
				continue
			}
			if err := m.provider.SendInvite(ctx, acct, sessionID, fr.XUID); err != nil {
				m.log.Errorf("send invite to %s for %s: %v", fr.Gamertag, acct.Gamertag(), err)
				continue
			}
			m.log.Debugf("sent invite to %s (%s) for %s", fr.Gamertag, fr.XUID, acct.Gamertag())
			m.markInvited(acct.Gamertag(), fr.XUID)
		}
	})
}

func (m *Manager) shouldInvite(tag, xuid string) bool {
	if m.opts.InviteEvery <= 0 {
		return true
	}
	key := tag + ":" + xuid
	m.inviteMu.Lock()
	defer m.inviteMu.Unlock()
	last, ok := m.lastInvite[key]
	if !ok {
		return true
	}
	return time.Since(last) >= m.opts.InviteEvery
}

func (m *Manager) markInvited(tag, xuid string) {
	key := tag + ":" + xuid
	m.inviteMu.Lock()
	if m.lastInvite == nil {
		m.lastInvite = map[string]time.Time{}
	}
	m.lastInvite[key] = time.Now()
	m.inviteMu.Unlock()
}

func (m *Manager) AutoAdd(ctx context.Context, gamertag string) error {
	if gamertag == "" {
		return errors.New("missing gamertag")
	}
	m.accounts.WithAccounts(func(acct *account.Account) {
		if err := m.provider.AddFriend(ctx, acct, gamertag); err != nil {
			m.log.Errorf("auto add %s to %s: %v", gamertag, acct.Gamertag(), err)
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
