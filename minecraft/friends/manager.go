package friends

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/cjmustard/console-connect/minecraft/account"
	"github.com/cjmustard/console-connect/minecraft/logger"
	"github.com/cjmustard/console-connect/minecraft/notifications"
)

type Friend struct {
	Gamertag string    `json:"gamertag"`
	Added    time.Time `json:"added"`
	Online   bool      `json:"online"`
}

type Provider interface {
	ListFriends(ctx context.Context, acct *account.Account) ([]Friend, error)
	AddFriend(ctx context.Context, acct *account.Account, gamertag string) error
	RemoveFriend(ctx context.Context, acct *account.Account, gamertag string) error
}

type Manager struct {
	log      *logger.Logger
	accounts *account.Manager
	provider Provider
	friends  map[string][]Friend
	mu       sync.RWMutex
	notify   notifications.Manager
}

func NewManager(log *logger.Logger, accounts *account.Manager, provider Provider, notify notifications.Manager) *Manager {
	if notify == nil {
		notify = notifications.NewManager(log, notifications.Config{})
	}
	return &Manager{log: log, accounts: accounts, provider: provider, friends: map[string][]Friend{}, notify: notify}
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
				m.log.Errorf("list friends for %s: %v", ac.Gamertag, err)
				once.Do(func() { firstErr = err })
				return
			}

			m.mu.Lock()
			m.friends[ac.Gamertag] = friends
			m.mu.Unlock()
		}(acct)
	})

	wg.Wait()
	return firstErr
}

func (m *Manager) AutoAdd(ctx context.Context, gamertag string) error {
	if gamertag == "" {
		return errors.New("missing gamertag")
	}
	m.accounts.WithAccounts(func(acct *account.Account) {
		if err := m.provider.AddFriend(ctx, acct, gamertag); err != nil {
			m.log.Errorf("auto add %s to %s: %v", gamertag, acct.Gamertag, err)
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

func copySlice(dst, src []Friend) {
	for i := range src {
		dst[i] = src[i]
	}
}
