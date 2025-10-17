package session

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/sandertv/gophertunnel/minecraft"
	"github.com/sandertv/gophertunnel/minecraft/protocol"
	"github.com/sandertv/gophertunnel/minecraft/protocol/packet"

	"github.com/cjmustard/consoleconnect/broadcast/account"
	"github.com/cjmustard/consoleconnect/broadcast/constants"
	"github.com/cjmustard/consoleconnect/broadcast/logger"
	"github.com/cjmustard/consoleconnect/broadcast/nether"
)

type Manager struct {
	log         *logger.Logger
	accounts    *account.Manager
	listener    *minecraft.Listener
	conns       map[string]*minecraft.Conn
	connMu      sync.RWMutex
	subsessions map[string]*SubSession
	subsMu      sync.RWMutex
	httpClient  *http.Client
	handles     map[string]bool
	handleMu    sync.Mutex
	states      map[string]*sessionState
	stateMu     sync.Mutex
	nether      *nether.Manager
}

type Options struct {
	Addr     string
	Provider minecraft.ServerStatusProvider
}

type SubSession struct {
	Account  *account.Account
	Conn     *minecraft.Conn
	LastPing time.Time
	Metadata map[string]any
	mu       sync.RWMutex
}

func NewManager(log *logger.Logger, accounts *account.Manager, netherMgr *nether.Manager, httpClient *http.Client) *Manager {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}
	return &Manager{
		log:         log,
		accounts:    accounts,
		conns:       map[string]*minecraft.Conn{},
		subsessions: map[string]*SubSession{},
		handles:     map[string]bool{},
		httpClient:  httpClient,
		states:      map[string]*sessionState{},
		nether:      netherMgr,
	}
}

func (m *Manager) Start(ctx context.Context) {
	m.accounts.WithAccounts(func(acct *account.Account) {
		if err := m.ensureSession(ctx, acct); err != nil {
			m.log.Errorf("create session for %s: %v", acct.Gamertag(), err)
			return
		}
		m.ensureSessionHandle(ctx, acct)
		if !acct.ShowAsOnline() {
			return
		}
		go m.runPresence(ctx, acct)
	})
	go m.refreshSessions(ctx)
}

func (m *Manager) ensureSessionHandle(ctx context.Context, acct *account.Account) {
	sessionID := acct.SessionID()
	if sessionID == "" {
		return
	}

	m.handleMu.Lock()
	if m.handles[sessionID] {
		m.handleMu.Unlock()
		return
	}
	m.handleMu.Unlock()

	tok, err := acct.Token(ctx, constants.RelyingPartyXboxLive)
	if err != nil {
		m.log.Errorf("fetch token for handle %s: %v", acct.Gamertag(), err)
		return
	}

	payload, err := json.Marshal(NewActivityHandle(sessionID))
	if err != nil {
		m.log.Errorf("marshal handle request for %s: %v", acct.Gamertag(), err)
		return
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, constants.CreateHandleURL, bytes.NewReader(payload))
	if err != nil {
		m.log.Errorf("build handle request for %s: %v", acct.Gamertag(), err)
		return
	}
	req.Header.Set("Authorization", tok.Header)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-xbl-contract-version", "107")

	resp, err := m.httpClient.Do(req)
	if err != nil {
		m.log.Errorf("create session handle for %s: %v", acct.Gamertag(), err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		m.log.Errorf("create session handle for %s: status %d: %s", acct.Gamertag(), resp.StatusCode, strings.TrimSpace(string(body)))
		return
	}

	m.handleMu.Lock()
	m.handles[sessionID] = true
	m.handleMu.Unlock()
}

func (m *Manager) runPresence(ctx context.Context, acct *account.Account) {
	backoff := 10 * time.Second
	maxBackoff := 5 * time.Minute
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		delay, err := m.updatePresence(ctx, acct)
		if err != nil {
			m.log.Errorf("presence update for %s: %v", acct.Gamertag(), err)
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return
			}
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
			continue
		}

		backoff = 10 * time.Second
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return
		}
	}
}

func (m *Manager) updatePresence(ctx context.Context, acct *account.Account) (time.Duration, error) {
	if err := m.ensureSession(ctx, acct); err != nil {
		m.log.Errorf("ensure session for %s: %v", acct.Gamertag(), err)
	}
	tok, err := acct.Token(ctx, constants.RelyingPartyXboxLive)
	if err != nil {
		return time.Minute, fmt.Errorf("token: %w", err)
	}
	if tok.XUID == "" {
		return time.Minute, fmt.Errorf("missing xuid for %s", acct.Gamertag())
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, constants.UserPresenceURL(tok.XUID), strings.NewReader(`{"state":"active"}`))
	if err != nil {
		return time.Minute, err
	}
	req.Header.Set("Authorization", tok.Header)
	req.Header.Set("x-xbl-contract-version", "3")
	req.Header.Set("Content-Type", "application/json")

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return time.Minute, fmt.Errorf("presence request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return time.Minute, fmt.Errorf("presence status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	heartbeat := 300
	if header := resp.Header.Get("X-Heartbeat-After"); header != "" {
		if v, err := strconv.Atoi(header); err == nil && v > 0 {
			heartbeat = v
		}
	}

	acct.UpdateStatus(account.StatusOnline, map[string]any{
		"heartbeatAfter":  heartbeat,
		"presenceUpdated": time.Now(),
	})

	return time.Duration(heartbeat) * time.Second, nil
}

func (m *Manager) ensureSession(ctx context.Context, acct *account.Account) error {
	state := m.sessionState(acct)

	if m.nether != nil {
		netherID, err := m.nether.NetworkID(ctx, acct)
		if err != nil {
			return fmt.Errorf("nether network id: %w", err)
		}
		state.setNetherNetID(netherID)
	}

	if !state.needsSync() {
		return nil
	}

	if state.netherNetID == nil {
		return fmt.Errorf("nether network id unavailable")
	}

	tok, err := acct.Token(ctx, constants.RelyingPartyXboxLive)
	if err != nil {
		return fmt.Errorf("token: %w", err)
	}
	if tok.XUID == "" {
		return fmt.Errorf("missing xuid for %s", acct.Gamertag())
	}

	titleID, _ := strconv.Atoi(constants.TitleID)
	payload := createSessionRequest{
		Members: map[string]sessionMember{
			"me": {
				Constants: map[string]memberConstantsSystem{
					"system": {
						XUID:       tok.XUID,
						Initialize: true,
					},
				},
				Properties: map[string]memberPropertiesSystem{
					"system": {
						Active:     true,
						Connection: state.connectionID,
						Subscription: memberSubscription{
							ID:          uuid.NewString(),
							ChangeTypes: []string{"everything"},
						},
					},
				},
			},
		},
		Properties: sessionProperties{
			System: sessionSystemProperties{
				JoinRestriction: "followed",
				ReadRestriction: "followed",
				Closed:          false,
			},
			Custom: sessionCustomProperties{
				BroadcastSetting:        3,
				CrossPlayDisabled:       false,
				Joinability:             "joinable_by_friends",
				LanGame:                 false,
				MaxMemberCount:          8,
				MemberCount:             1,
				OnlineCrossPlatformGame: true,
				SupportedConnections: []sessionConnection{{
					ConnectionType: constants.ConnectionTypeWebRTC,
					HostIPAddress:  "",
					HostPort:       0,
					NetherNetID:    netherNetID{state.netherNetID},
				}},
				TitleID:        titleID,
				TransportLayer: 2,
				LevelID:        "level",
				HostName:       defaultHostName(acct.Gamertag()),
				OwnerID:        tok.XUID,
				RakNetGUID:     "",
				WorldName:      defaultWorldName(acct.Gamertag()),
				WorldType:      "Survival",
				Protocol:       protocol.CurrentProtocol,
				Version:        protocol.CurrentVersion,
				IsEditorWorld:  false,
				IsHardcore:     false,
			},
		},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("encode session payload: %w", err)
	}

	url := fmt.Sprintf(constants.CreateSessionURL, state.sessionID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build session request: %w", err)
	}
	req.Header.Set("Authorization", tok.Header)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-xbl-contract-version", "107")

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("create session request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("create session status %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}

	state.markSynced()
	return nil
}

func (m *Manager) refreshSessions(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.accounts.WithAccounts(func(acct *account.Account) {
				if err := m.ensureSession(ctx, acct); err != nil {
					m.log.Errorf("refresh session for %s: %v", acct.Gamertag(), err)
				}
			})
		}
	}
}

func (m *Manager) sessionState(acct *account.Account) *sessionState {
	sessionID := acct.SessionID()
	m.stateMu.Lock()
	defer m.stateMu.Unlock()
	state, ok := m.states[sessionID]
	if ok {
		return state
	}
	state = &sessionState{
		sessionID:    sessionID,
		connectionID: uuid.NewString(),
	}
	m.states[sessionID] = state
	return state
}

func defaultHostName(gamertag string) string {
	if gamertag == "" {
		return "Console Connect"
	}
	return fmt.Sprintf("%s's World", gamertag)
}

func defaultWorldName(gamertag string) string {
	if gamertag == "" {
		return "Minecraft World"
	}
	return fmt.Sprintf("%s Realm", gamertag)
}

type sessionState struct {
	sessionID    string
	connectionID string
	netherNetID  *big.Int

	mu       sync.Mutex
	lastSync time.Time
}

func (s *sessionState) needsSync() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.netherNetID == nil {
		return true
	}
	if s.lastSync.IsZero() {
		return true
	}
	return time.Since(s.lastSync) > time.Minute
}

func (s *sessionState) markSynced() {
	s.mu.Lock()
	s.lastSync = time.Now()
	s.mu.Unlock()
}

func (s *sessionState) setNetherNetID(id uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.netherNetID != nil && s.netherNetID.Uint64() == id {
		return
	}
	s.netherNetID = new(big.Int).SetUint64(id)
	s.lastSync = time.Time{}
}

func (m *Manager) Listen(ctx context.Context, opts Options) error {
	if opts.Provider == nil {
		opts.Provider = minecraft.NewStatusProvider("Broadcaster", "Minecraft Presence Relay")
	}
	listener, err := minecraft.ListenConfig{
		StatusProvider: opts.Provider,
		PacketFunc:     m.handlePackets,
	}.Listen("raknet", opts.Addr)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}

	m.listener = listener
	go func() {
		<-ctx.Done()
		listener.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			m.log.Errorf("accept connection: %v", err)
			continue
		}
		m.log.Debugf("client connected: %s", conn.RemoteAddr())
		go m.handleConn(ctx, conn.(*minecraft.Conn))
	}
}

func (m *Manager) handleConn(ctx context.Context, conn *minecraft.Conn) {
	m.connMu.Lock()
	m.conns[conn.RemoteAddr().String()] = conn
	m.connMu.Unlock()

	if err := conn.StartGame(minecraft.GameData{}); err != nil {
		m.log.Errorf("start game: %v", err)
		conn.Close()
		return
	}

	<-ctx.Done()
	conn.Close()
}

func (m *Manager) handlePackets(header packet.Header, payload []byte, src net.Addr, dst net.Addr) {
	subs := m.getSubSession(src.String())
	if subs == nil {
		return
	}
	subs.UpdateLastPing()
}

func (m *Manager) getSubSession(addr string) *SubSession {
	m.subsMu.RLock()
	defer m.subsMu.RUnlock()
	return m.subsessions[addr]
}

func (m *Manager) RegisterSubSession(addr string, acct *account.Account, conn *minecraft.Conn) *SubSession {
	subs := &SubSession{Account: acct, Conn: conn, LastPing: time.Now(), Metadata: map[string]any{}}
	m.subsMu.Lock()
	m.subsessions[addr] = subs
	m.subsMu.Unlock()
	return subs
}

func (m *Manager) Snapshot() []map[string]any {
	m.subsMu.RLock()
	defer m.subsMu.RUnlock()
	result := make([]map[string]any, 0, len(m.subsessions))
	for addr, subs := range m.subsessions {
		entry := subs.Snapshot()
		entry["remoteAddr"] = addr
		if subs.Account != nil {
			entry["gamertag"] = subs.Account.Gamertag
		}
		result = append(result, entry)
	}
	return result
}

func (m *Manager) Close(addr string) {
	m.connMu.Lock()
	if conn, ok := m.conns[addr]; ok {
		conn.Close()
		delete(m.conns, addr)
	}
	m.connMu.Unlock()

	m.subsMu.Lock()
	delete(m.subsessions, addr)
	m.subsMu.Unlock()
}

func (s *SubSession) UpdateLastPing() {
	s.mu.Lock()
	s.LastPing = time.Now()
	s.mu.Unlock()
}

func (s *SubSession) SetMetadata(key string, value any) {
	s.mu.Lock()
	if s.Metadata == nil {
		s.Metadata = map[string]any{}
	}
	s.Metadata[key] = value
	s.mu.Unlock()
}

func (s *SubSession) Snapshot() map[string]any {
	s.mu.RLock()
	defer s.mu.RUnlock()
	copy := map[string]any{"lastPing": s.LastPing}
	for k, v := range s.Metadata {
		copy[k] = v
	}
	return copy
}
