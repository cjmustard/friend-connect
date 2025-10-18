package xbox

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/sandertv/gophertunnel/minecraft/auth"
	"github.com/sandertv/gophertunnel/minecraft/auth/authclient"
	"golang.org/x/oauth2"
)

const (
	ServiceConfigID = "4fc10100-5f7a-4470-899b-280835760c07"
	TemplateName    = "MinecraftLobby"
	TitleID         = "896928775"
	PlayfabLoginURL = "https://20ca2.playfabapi.com/Client/LoginWithXbox"

	RelyingPartyXboxLive    = "http://xboxlive.com"
	RelyingPartyMultiplayer = "https://multiplayer.minecraft.net/"
	RelyingPartyPlayFab     = "https://b980a380.minecraft.playfabapi.com/"
)

var (
	RtaWebsocketURL      = "wss://rta.xboxlive.com/connect"
	FollowersURL         = "https://peoplehub.xboxlive.com/users/me/people/followers"
	SocialURL            = "https://peoplehub.xboxlive.com/users/me/people/social"
	SocialSummaryURL     = "https://social.xboxlive.com/users/me/summary"
	WebsocketDialTimeout = 10 * time.Second
	ConnectionTypeWebRTC = 3
	MaxFriends           = 2000
)

func PeopleURL(xuid string) string {
	return "https://social.xboxlive.com/users/me/people/xuid(" + xuid + ")"
}

func UserPresenceURL(xuid string) string {
	return "https://userpresence.xboxlive.com/users/xuid(" + xuid + ")/devices/current/titles/current"
}

func ProfileSettingsURL(xuid string) string {
	return "https://profile.xboxlive.com/users/me/profile/settings?settings=Gamertag"
}

func FollowerURL(xuid string) string {
	return "https://social.xboxlive.com/users/me/people/follower/xuid(" + xuid + ")"
}

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

// NewStore creates a new account store for managing Xbox Live accounts.
func NewStore() *Store {
	return &Store{
		accounts:   map[string]*Account{},
		byGamertag: map[string]*Account{},
	}
}

// Register creates a new account from an OAuth2 token.
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
		if tok, err := acct.tokenMgr.Acquire(ctx, RelyingPartyXboxLive); err == nil {
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

// WithAccounts calls the provided function for each registered account.
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

// Token retrieves an Xbox Live token for the specified relying party.
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

// AuthorizationHeader returns the authorization header for Xbox Live API requests.
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

// Gamertag returns the account's Xbox Live gamertag.
func (a *Account) Gamertag() string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.gamertag
}

// XUID returns the account's Xbox Live user ID.
func (a *Account) XUID() string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.xuid
}

// SessionID returns the account's unique session identifier.
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

type Token struct {
	Header   string
	Gamertag string
	XUID     string
	UserHash string
	Raw      string
	Expiry   time.Time
}

type TokenManager struct {
	src      oauth2.TokenSource
	tokens   map[string]*Token
	onUpdate func(*Token)
	mu       sync.Mutex
	client   *authclient.AuthClient
}

// NewTokenManager creates a new token manager from a refresh token.
func NewTokenManager(refreshToken string, onUpdate func(*Token)) *TokenManager {
	if refreshToken == "" {
		return nil
	}
	seed := &oauth2.Token{RefreshToken: refreshToken, Expiry: time.Now().Add(-time.Hour)}
	return NewTokenManagerFromToken(seed, onUpdate)
}

// NewTokenManagerFromToken creates a new token manager from an OAuth2 token.
func NewTokenManagerFromToken(seed *oauth2.Token, onUpdate func(*Token)) *TokenManager {
	if seed == nil || seed.RefreshToken == "" {
		return nil
	}
	clone := *seed
	if clone.Expiry.IsZero() || time.Until(clone.Expiry) > 0 {
		clone.Expiry = time.Now().Add(-time.Minute)
	}
	base := auth.RefreshTokenSource(&clone)
	return NewTokenManagerFromSource(oauth2.ReuseTokenSource(&clone, base), onUpdate)
}

// NewTokenManagerFromSource creates a new token manager from a token source.
func NewTokenManagerFromSource(src oauth2.TokenSource, onUpdate func(*Token)) *TokenManager {
	if src == nil {
		return nil
	}
	return &TokenManager{
		src:      src,
		tokens:   map[string]*Token{},
		onUpdate: onUpdate,
		client:   authclient.DefaultClient,
	}
}

// Acquire retrieves or creates a token for the specified relying party.
func (m *TokenManager) Acquire(ctx context.Context, relyingParty string) (*Token, error) {
	if m == nil {
		return nil, errors.New("token manager not initialised")
	}
	m.mu.Lock()
	tok := m.tokens[relyingParty]
	if tok != nil && time.Until(tok.Expiry) > time.Minute {
		m.mu.Unlock()
		return tok, nil
	}
	m.mu.Unlock()

	liveToken, err := m.src.Token()
	if err != nil {
		return nil, fmt.Errorf("obtain live token: %w", err)
	}
	xblToken, err := auth.RequestXBLToken(ctx, m.client, liveToken, relyingParty)
	if err != nil {
		return nil, fmt.Errorf("request xbl token: %w", err)
	}
	parsed, err := fromXBLToken(xblToken)
	if err != nil {
		return nil, err
	}

	m.mu.Lock()
	m.tokens[relyingParty] = parsed
	m.mu.Unlock()

	if m.onUpdate != nil {
		m.onUpdate(parsed)
	}
	return parsed, nil
}

func fromXBLToken(xbl *auth.XBLToken) (*Token, error) {
	if xbl == nil || len(xbl.AuthorizationToken.DisplayClaims.UserInfo) == 0 {
		return nil, errors.New("empty xbox token response")
	}
	info := xbl.AuthorizationToken.DisplayClaims.UserInfo[0]
	expiry := parseTokenExpiry(xbl.AuthorizationToken.Token)
	return &Token{
		Header:   fmt.Sprintf("XBL3.0 x=%s;%s", info.UserHash, xbl.AuthorizationToken.Token),
		Gamertag: info.GamerTag,
		XUID:     info.XUID,
		UserHash: info.UserHash,
		Raw:      xbl.AuthorizationToken.Token,
		Expiry:   expiry,
	}, nil
}

func parseTokenExpiry(raw string) time.Time {
	fallback := time.Now().Add(30 * time.Minute)
	parts := strings.Split(raw, ".")
	if len(parts) < 2 {
		return fallback
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return fallback
	}
	var payload struct {
		Exp       int64  `json:"exp"`
		ExpiresOn string `json:"ExpiresOn"`
		NotAfter  string `json:"NotAfter"`
	}
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return fallback
	}
	if payload.Exp != 0 {
		return time.Unix(payload.Exp, 0)
	}
	if payload.ExpiresOn != "" {
		if secs, err := strconv.ParseInt(payload.ExpiresOn, 10, 64); err == nil {
			return time.Unix(secs, 0)
		}
	}
	if payload.NotAfter != "" {
		if t, err := time.Parse(time.RFC3339, payload.NotAfter); err == nil {
			return t
		}
	}
	return fallback
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
