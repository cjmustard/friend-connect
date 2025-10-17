package account

import (
	"context"
	"errors"
	"sync"
	"time"
)

type Status int

const (
	StatusOffline Status = iota
	StatusOnline
	StatusPlaying
)

type Account struct {
	Gamertag string
	Token    string
	Status   Status
	LastSeen time.Time
	metadata map[string]any
	mu       sync.RWMutex
}

type Manager struct {
	accounts map[string]*Account
	mu       sync.RWMutex
}

func NewManager() *Manager {
	return &Manager{accounts: map[string]*Account{}}
}

func (m *Manager) Register(ctx context.Context, gamertag, token string) (*Account, error) {
	if gamertag == "" || token == "" {
		return nil, errors.New("missing gamertag or token")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	acct := &Account{Gamertag: gamertag, Token: token, Status: StatusOffline, LastSeen: time.Now(), metadata: map[string]any{}}
	m.accounts[gamertag] = acct
	return acct, nil
}

func (m *Manager) Get(gamertag string) (*Account, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	acct, ok := m.accounts[gamertag]
	return acct, ok
}

func (a *Account) UpdateStatus(status Status, metadata map[string]any) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.Status = status
	a.LastSeen = time.Now()
	if metadata != nil {
		for k, v := range metadata {
			a.metadata[k] = v
		}
	}
}

func (a *Account) Metadata(key string) (any, bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	v, ok := a.metadata[key]
	return v, ok
}

func (a *Account) Snapshot() Account {
	a.mu.RLock()
	defer a.mu.RUnlock()
	copy := *a
	copy.metadata = map[string]any{}
	for k, v := range a.metadata {
		copy.metadata[k] = v
	}
	return copy
}

func (m *Manager) All() []Account {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]Account, 0, len(m.accounts))
	for _, acct := range m.accounts {
		result = append(result, acct.Snapshot())
	}
	return result
}

func (m *Manager) WithAccounts(fn func(*Account)) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, acct := range m.accounts {
		fn(acct)
	}
}
