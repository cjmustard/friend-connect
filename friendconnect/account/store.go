package account

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/google/uuid"
	"golang.org/x/oauth2"

	"github.com/sandertv/gophertunnel/minecraft/auth"

	"github.com/cjmustard/friend-connect/friendconnect/constants"
)

type Status int

const (
	StatusOffline Status = iota
	StatusOnline
	StatusPlaying
)

type Account struct {
	store       *Store
	tokenMgr    *TokenManager
	tokenSource oauth2.TokenSource

	gamertag  string
	sessionID string

	status   Status
	lastSeen time.Time
	metadata map[string]any

	xuid     string
	userHash string

	mu sync.RWMutex
}

type Store struct {
	accounts   map[string]*Account
	byGamertag map[string]*Account
	mu         sync.RWMutex
}

func NewStore() *Store {
	return &Store{
		accounts:   map[string]*Account{},
		byGamertag: map[string]*Account{},
	}
}

func (s *Store) Register(ctx context.Context, seed *oauth2.Token) (*Account, error) {
	if seed == nil || seed.RefreshToken == "" {
		return nil, errors.New("missing refresh token")
	}
	clone := cloneToken(seed)
	if clone.Expiry.IsZero() || time.Until(clone.Expiry) > 0 {
		clone.Expiry = time.Now().Add(-time.Minute)
	}

	acct := &Account{
		store:       s,
		sessionID:   uuid.NewString(),
		status:      StatusOffline,
		lastSeen:    time.Now(),
		metadata:    map[string]any{},
		tokenSource: oauth2.ReuseTokenSource(clone, authTokenSource(clone)),
	}
	acct.tokenMgr = NewTokenManagerFromToken(clone, func(tok *Token) {
		s.applyToken(acct, tok)
	})

	s.mu.Lock()
	s.accounts[acct.sessionID] = acct
	s.mu.Unlock()

	if ctx == nil {
		ctx = context.Background()
	}
	if acct.tokenMgr != nil {
		if tok, err := acct.tokenMgr.Acquire(ctx, constants.RelyingPartyXboxLive); err == nil {
			s.applyToken(acct, tok)
		}
	}

	return acct, nil
}

func (s *Store) applyToken(acct *Account, tok *Token) {
	if acct == nil || tok == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	oldTag := acct.gamertag

	acct.mu.Lock()
	if tok.Gamertag != "" {
		acct.gamertag = tok.Gamertag
	}
	acct.xuid = tok.XUID
	acct.userHash = tok.UserHash
	acct.mu.Unlock()

	if oldTag != "" {
		delete(s.byGamertag, oldTag)
	}
	if acct.gamertag != "" {
		s.byGamertag[acct.gamertag] = acct
	}
}

func (s *Store) Get(gamertag string) (*Account, bool) {
	s.mu.RLock()
	acct, ok := s.byGamertag[gamertag]
	s.mu.RUnlock()
	return acct, ok
}

func (s *Store) WithAccounts(fn func(*Account)) {
	s.mu.RLock()
	accounts := make([]*Account, 0, len(s.accounts))
	for _, acct := range s.accounts {
		accounts = append(accounts, acct)
	}
	s.mu.RUnlock()

	for _, acct := range accounts {
		fn(acct)
	}
}

func (a *Account) Token(ctx context.Context, relyingParty string) (*Token, error) {
	if a.tokenMgr == nil {
		return nil, errors.New("token manager not initialised")
	}
	tok, err := a.tokenMgr.Acquire(ctx, relyingParty)
	if err != nil {
		return nil, err
	}
	a.store.applyToken(a, tok)
	return tok, nil
}

func (a *Account) AuthorizationHeader(ctx context.Context, relyingParty string) (string, error) {
	tok, err := a.Token(ctx, relyingParty)
	if err != nil {
		return "", err
	}
	return tok.Header, nil
}

func (a *Account) TokenSource() oauth2.TokenSource {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.tokenSource
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
		if a.metadata == nil {
			a.metadata = map[string]any{}
		}
		for k, v := range metadata {
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

func cloneToken(tok *oauth2.Token) *oauth2.Token {
	if tok == nil {
		return nil
	}
	clone := *tok
	return &clone
}

func authTokenSource(tok *oauth2.Token) oauth2.TokenSource {
	if tok == nil {
		return nil
	}
	return auth.RefreshTokenSource(tok)
}
