package account

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/cjmustard/consoleconnect/broadcast/xbox"
)

type Status int

const (
	StatusOffline Status = iota
	StatusOnline
	StatusPlaying
)

type Options struct {
	Gamertag     string
	RefreshToken string
	ShowAsOnline bool
	PreferredIPs []string
}

type Account struct {
	manager  *Manager
	tokenMgr *xbox.TokenManager

	gamertag     string
	refreshToken string
	showOnline   bool
	preferredIPs []string
	sessionID    string

	status   Status
	lastSeen time.Time
	metadata map[string]any

	xuid     string
	userHash string

	mu sync.RWMutex
}

type Manager struct {
	accounts map[string]*Account
	mu       sync.RWMutex
}

func NewManager() *Manager {
	return &Manager{accounts: map[string]*Account{}}
}

func (m *Manager) Register(ctx context.Context, opts Options) (*Account, error) {
	if opts.RefreshToken == "" {
		return nil, errors.New("missing refresh token")
	}
	acct := &Account{
		manager:      m,
		gamertag:     opts.Gamertag,
		refreshToken: opts.RefreshToken,
		showOnline:   opts.ShowAsOnline,
		preferredIPs: append([]string(nil), opts.PreferredIPs...),
		sessionID:    uuid.NewString(),
		status:       StatusOffline,
		lastSeen:     time.Now(),
		metadata:     map[string]any{},
	}
	acct.tokenMgr = xbox.NewTokenManager(opts.RefreshToken, func(tok *xbox.Token) {
		m.applyToken(acct, tok)
	})

	m.mu.Lock()
	m.accounts[acct.gamertag] = acct
	m.mu.Unlock()
	return acct, nil
}

func (m *Manager) applyToken(acct *Account, tok *xbox.Token) {
	if tok == nil {
		return
	}
	m.mu.Lock()
	oldTag := acct.gamertag
	acct.mu.Lock()
	if tok.Gamertag != "" {
		acct.gamertag = tok.Gamertag
	}
	acct.xuid = tok.XUID
	acct.userHash = tok.UserHash
	acct.mu.Unlock()
	if acct.gamertag != oldTag && oldTag != "" {
		delete(m.accounts, oldTag)
		m.accounts[acct.gamertag] = acct
	}
	m.mu.Unlock()
}

func (m *Manager) Get(gamertag string) (*Account, bool) {
	m.mu.RLock()
	acct, ok := m.accounts[gamertag]
	m.mu.RUnlock()
	return acct, ok
}

func (a *Account) Token(ctx context.Context, relyingParty string) (*xbox.Token, error) {
	if a.tokenMgr == nil {
		return nil, errors.New("token manager not initialised")
	}
	tok, err := a.tokenMgr.Acquire(ctx, relyingParty)
	if err != nil {
		return nil, err
	}
	a.manager.applyToken(a, tok)
	return tok, nil
}

func (a *Account) AuthorizationHeader(ctx context.Context, relyingParty string) (string, error) {
	tok, err := a.Token(ctx, relyingParty)
	if err != nil {
		return "", err
	}
	return tok.Header, nil
}

func (a *Account) Gamertag() string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.gamertag
}

func (a *Account) XUID() string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.xuid
}

func (a *Account) ShowAsOnline() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.showOnline
}

func (a *Account) PreferredIPs() []string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	out := make([]string, len(a.preferredIPs))
	copy(out, a.preferredIPs)
	return out
}

func (a *Account) RefreshToken() string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.refreshToken
}

func (a *Account) SessionID() string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.sessionID
}

func (a *Account) UpdateStatus(status Status, metadata map[string]any) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.status = status
	a.lastSeen = time.Now()
	if metadata != nil {
		for k, v := range metadata {
			if a.metadata == nil {
				a.metadata = map[string]any{}
			}
			a.metadata[k] = v
		}
	}
}

func (a *Account) Metadata(key string) (any, bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.metadata == nil {
		return nil, false
	}
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
	copy.preferredIPs = append([]string(nil), a.preferredIPs...)
	return copy
}

func (m *Manager) All() []Account {
	m.mu.RLock()
	accounts := make([]*Account, 0, len(m.accounts))
	for _, acct := range m.accounts {
		accounts = append(accounts, acct)
	}
	m.mu.RUnlock()

	result := make([]Account, 0, len(accounts))
	for _, acct := range accounts {
		result = append(result, acct.Snapshot())
	}
	return result
}

func (m *Manager) WithAccounts(fn func(*Account)) {
	m.mu.RLock()
	accounts := make([]*Account, 0, len(m.accounts))
	for _, acct := range m.accounts {
		accounts = append(accounts, acct)
	}
	m.mu.RUnlock()

	for _, acct := range accounts {
		fn(acct)
	}
}
