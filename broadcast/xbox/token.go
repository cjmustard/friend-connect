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

	"github.com/sandertv/gophertunnel/minecraft/auth"
	"github.com/sandertv/gophertunnel/minecraft/auth/authclient"
	"golang.org/x/oauth2"
)

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

func NewTokenManager(refreshToken string, onUpdate func(*Token)) *TokenManager {
	if refreshToken == "" {
		return nil
	}
	seed := &oauth2.Token{RefreshToken: refreshToken, Expiry: time.Now().Add(-time.Hour)}
	return NewTokenManagerFromToken(seed, onUpdate)
}

func NewTokenManagerFromToken(seed *oauth2.Token, onUpdate func(*Token)) *TokenManager {
	if seed == nil || seed.RefreshToken == "" {
		return nil
	}
	clone := *seed
	if clone.Expiry.IsZero() || time.Until(clone.Expiry) > 0 {
		// Force the first call to refresh immediately so the manager always
		// works with a fresh access token derived from the refresh token.
		clone.Expiry = time.Now().Add(-time.Minute)
	}
	base := auth.RefreshTokenSource(&clone)
	return NewTokenManagerFromSource(oauth2.ReuseTokenSource(&clone, base), onUpdate)
}

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
