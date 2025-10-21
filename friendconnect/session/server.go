package session

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/df-mc/go-nethernet"
	"github.com/df-mc/go-xsapi"
	"github.com/df-mc/go-xsapi/mpsd"
	"github.com/go-gl/mathgl/mgl32"
	"github.com/google/uuid"
	"github.com/sandertv/go-raknet"
	"github.com/sandertv/gophertunnel/minecraft"
	"github.com/sandertv/gophertunnel/minecraft/protocol"
	"github.com/sandertv/gophertunnel/minecraft/protocol/packet"
	"github.com/sandertv/gophertunnel/minecraft/room"

	"github.com/cjmustard/friend-connect/friendconnect/xbox"
)

type Server struct {
	log      *log.Logger
	accounts *xbox.Store
	listener *minecraft.Listener

	conns           map[string]*minecraft.Conn
	subsessions     map[string]*ClientSession
	announcers      map[string]*room.XBLAnnouncer
	sessions        map[string]*mpsd.Session
	statusMeta      map[string]*statusMetadata
	startedAccounts map[string]struct{}
	netherAccounts  map[string]struct{}

	httpClient     *http.Client
	nether         *SignalingHub
	netherProvider minecraft.ServerStatusProvider

	listenPort uint16
	listenGUID string
	netherCtx  context.Context

	relay      RelayOptions
	viewership ViewershipOptions
	relayCheck relayCheckState

	entityIDs atomic.Uint64
	ctx       context.Context

	mu sync.RWMutex
}

type Options struct {
	Addr     string
	Provider minecraft.ServerStatusProvider
}

type ClientSession struct {
	Account  *xbox.Account
	Conn     *minecraft.Conn
	LastPing time.Time
	Metadata map[string]any
	mu       sync.RWMutex
}

type statusMetadata struct {
	levelID string
}

type RelayOptions struct {
	RemoteAddress string
	VerifyTarget  bool
	Timeout       time.Duration
}

// ViewershipOptions defines how the session appears in Xbox Live and server browsers.
// These settings control the visibility, accessibility, and display information
// for the Minecraft session that will be broadcast to friends and other players.
type ViewershipOptions struct {
	// Joinability controls who can join the session (friends only, public, etc.)
	Joinability string
	// MaxMemberCount is the maximum number of players allowed to join the session
	MaxMemberCount int
	// MemberCount is the current number of players in the session
	MemberCount int
	// BroadcastSetting determines how visible the session is to others
	BroadcastSetting int32
	// WorldType is the game mode displayed to players (Survival, Creative, etc.)
	WorldType string
	// WorldName is the name of the world/server that will be displayed
	WorldName string
	// HostName is the name of the session host shown to other players
	HostName string
	// LanGame indicates whether this session is restricted to local network only
	LanGame bool
	// OnlineCrossPlatformGame enables cross-platform play between PC, mobile, and console
	OnlineCrossPlatformGame bool
	// CrossPlayDisabled disables cross-play functionality between different platforms
	CrossPlayDisabled bool
}

type relayCheckState struct {
	mu        sync.Mutex
	lastCheck time.Time
	err       error
}

// NewServer creates a new Minecraft server instance with the provided dependencies.
// The server handles Xbox Live session announcements and client connections.
func NewServer(logger *log.Logger, accounts *xbox.Store, netherHub *SignalingHub, httpClient *http.Client) *Server {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}
	if logger == nil {
		logger = log.New(os.Stdout, "", 0)
	}
	return &Server{
		log:             logger,
		accounts:        accounts,
		conns:           map[string]*minecraft.Conn{},
		subsessions:     map[string]*ClientSession{},
		httpClient:      httpClient,
		nether:          netherHub,
		announcers:      map[string]*room.XBLAnnouncer{},
		sessions:        map[string]*mpsd.Session{},
		statusMeta:      map[string]*statusMetadata{},
		startedAccounts: map[string]struct{}{},
		netherAccounts:  map[string]struct{}{},
		viewership: ViewershipOptions{
			Joinability:             room.JoinabilityJoinableByFriends,
			MaxMemberCount:          8,
			MemberCount:             1,
			BroadcastSetting:        room.BroadcastSettingFriendsOfFriends,
			WorldType:               "Survival",
			WorldName:               "",
			HostName:                "",
			LanGame:                 false,
			OnlineCrossPlatformGame: true,
			CrossPlayDisabled:       false,
		},
	}
}

// ConfigureRelay sets up the relay configuration for transferring clients to remote servers.
func (m *Server) ConfigureRelay(opts RelayOptions) {
	if opts.Timeout <= 0 {
		opts.Timeout = 5 * time.Second
	}
	m.relay = opts
}

// ConfigureViewership sets up the viewership options for session announcements.
func (m *Server) ConfigureViewership(opts ViewershipOptions) {
	if opts.MaxMemberCount <= 0 {
		opts.MaxMemberCount = 8
	}
	if opts.MemberCount <= 0 {
		opts.MemberCount = 1
	}
	if opts.WorldType == "" {
		opts.WorldType = "Survival"
	}
	if opts.Joinability == "" {
		opts.Joinability = room.JoinabilityJoinableByFriends
	}
	if opts.BroadcastSetting == 0 {
		opts.BroadcastSetting = room.BroadcastSettingFriendsOfFriends
	}
	m.viewership = opts
}

func (m *Server) Start(ctx context.Context) {
	if ctx == nil {
		ctx = context.Background()
	}
	m.setContext(ctx)
	m.accounts.WithAccounts(func(acct *xbox.Account) {
		m.startAccount(acct)
	})
	go m.refreshSessions(ctx)
}

func (m *Server) setContext(ctx context.Context) {
	m.mu.Lock()
	m.ctx = ctx
	m.mu.Unlock()
}

func (m *Server) sessionContext() context.Context {
	m.mu.RLock()
	ctx := m.ctx
	m.mu.RUnlock()
	if ctx == nil {
		return context.Background()
	}
	return ctx
}

func (m *Server) startAccount(acct *xbox.Account) {
	if acct == nil {
		return
	}
	id := acct.SessionID()
	m.mu.Lock()
	if _, ok := m.startedAccounts[id]; ok {
		m.mu.Unlock()
		return
	}
	m.startedAccounts[id] = struct{}{}
	m.mu.Unlock()

	ctx := m.sessionContext()
	go func() {
		if err := m.ensureSession(ctx, acct); err != nil {
			m.log.Printf("create session failed for %s: %v", acct.Gamertag(), err)
		}
	}()
	go m.runPresence(ctx, acct)
}

func (m *Server) AttachAccount(ctx context.Context, acct *xbox.Account) {
	if acct == nil {
		return
	}
	if ctx != nil {
		m.setContext(ctx)
	}
	m.startAccount(acct)
	provider, providerCtx := m.netherRuntime()
	if provider != nil && m.nether != nil {
		if providerCtx == nil {
			providerCtx = m.sessionContext()
		}
		m.startNetherForAccount(providerCtx, provider, acct)
	}
}

func (m *Server) setNetherRuntime(ctx context.Context, provider minecraft.ServerStatusProvider) {
	m.mu.Lock()
	m.netherCtx = ctx
	m.netherProvider = provider
	m.mu.Unlock()
}

func (m *Server) netherRuntime() (minecraft.ServerStatusProvider, context.Context) {
	m.mu.RLock()
	provider := m.netherProvider
	ctx := m.netherCtx
	m.mu.RUnlock()
	return provider, ctx
}

func (m *Server) startNetherForAccount(ctx context.Context, provider minecraft.ServerStatusProvider, acct *xbox.Account) {
	if acct == nil || provider == nil || m.nether == nil {
		return
	}
	if ctx == nil {
		ctx = m.sessionContext()
	}
	id := acct.SessionID()
	m.mu.Lock()
	if _, ok := m.netherAccounts[id]; ok {
		m.mu.Unlock()
		return
	}
	m.netherAccounts[id] = struct{}{}
	m.mu.Unlock()
	go m.listenNetherForAccount(ctx, provider, acct)
}

func (m *Server) runPresence(ctx context.Context, acct *xbox.Account) {

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		delay, err := m.updatePresence(ctx, acct)
		if err != nil {
			m.log.Printf("presence update failed for %s: %v", acct.Gamertag(), err)
			return
		}

		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return
		}
	}
}

func (m *Server) updatePresence(ctx context.Context, acct *xbox.Account) (time.Duration, error) {
	if err := m.ensureSession(ctx, acct); err != nil {
		return time.Minute, err
	}
	tok, err := acct.Token(ctx, xbox.RelyingPartyXboxLive)
	if err != nil {
		return time.Minute, fmt.Errorf("token: %w", err)
	}
	if tok.XUID == "" {
		return time.Minute, fmt.Errorf("missing xuid for %s", acct.Gamertag())
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, xbox.UserPresenceURL(tok.XUID), strings.NewReader(`{"state":"active"}`))
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

	acct.UpdateStatus(xbox.StatusOnline, map[string]any{
		"heartbeatAfter":  heartbeat,
		"presenceUpdated": time.Now(),
	})

	return time.Duration(heartbeat) * time.Second, nil
}

func (m *Server) ensureSession(ctx context.Context, acct *xbox.Account) error {
	if acct == nil {
		return errors.New("nil account")
	}
	tok, err := acct.Token(ctx, xbox.RelyingPartyXboxLive)
	if err != nil {
		return fmt.Errorf("token: %w", err)
	}
	status, err := m.buildStatus(ctx, acct, tok)
	if err != nil {
		return err
	}
	ann := m.announcerFor(acct)
	if ann == nil {
		return fmt.Errorf("failed to create announcer for %s", acct.Gamertag())
	}

	if err := func() (err error) {
		defer func() {
			if r := recover(); r != nil {
				err = fmt.Errorf("announcer panic: %v", r)
			}
		}()
		return ann.Announce(ctx, status)
	}(); err != nil {
		return fmt.Errorf("announce session: %w", err)
	}
	if ann.Session != nil {
		m.storeSession(acct.SessionID(), ann.Session)
	}
	return nil
}

func (m *Server) announcerFor(acct *xbox.Account) *room.XBLAnnouncer {
	sessionID := acct.SessionID()
	m.mu.Lock()
	defer m.mu.Unlock()
	if ann, ok := m.announcers[sessionID]; ok && ann != nil {
		return ann
	}
	scid := uuid.MustParse(xbox.ServiceConfigID)
	ann := &room.XBLAnnouncer{
		TokenSource: accountTokenSource{acct: acct},
		SessionReference: mpsd.SessionReference{
			ServiceConfigID: scid,
			TemplateName:    xbox.TemplateName,
			Name:            strings.ToUpper(sessionID),
		},
		PublishConfig: mpsd.PublishConfig{Client: m.httpClient},
	}
	m.announcers[sessionID] = ann
	return ann
}

func (m *Server) storeSession(id string, sess *mpsd.Session) {
	if sess == nil || id == "" {
		return
	}
	m.mu.Lock()
	m.sessions[id] = sess
	m.mu.Unlock()
}

func (m *Server) cleanup() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, ann := range m.announcers {
		if ann != nil {
			func() {
				defer func() {
					if r := recover(); r != nil {
						m.log.Printf("warning: announcer cleanup panic: %v", r)
					}
				}()
				ann.Close()
			}()
		}
	}
	m.announcers = map[string]*room.XBLAnnouncer{}
}

func (m *Server) Reset() {
	m.log.Printf("resetting server state...")
	m.cleanup()

	m.mu.Lock()
	for _, conn := range m.conns {
		if conn != nil {
			conn.Close()
		}
	}
	m.conns = map[string]*minecraft.Conn{}

	for _, sess := range m.subsessions {
		if sess != nil && sess.Conn != nil {
			sess.Conn.Close()
		}
	}
	m.subsessions = map[string]*ClientSession{}
	m.sessions = map[string]*mpsd.Session{}
	m.startedAccounts = map[string]struct{}{}
	m.netherAccounts = map[string]struct{}{}
	m.mu.Unlock()

	m.log.Printf("server state reset complete")
}

func (m *Server) buildStatus(ctx context.Context, acct *xbox.Account, tok *xbox.Token) (room.Status, error) {
	hostName := m.viewership.HostName
	if hostName == "" {
		hostName = defaultHostName(acct.Gamertag())
	}

	worldName := m.viewership.WorldName
	if worldName == "" {
		worldName = defaultWorldName(acct.Gamertag())
	}

	status := room.Status{
		Joinability:             m.viewership.Joinability,
		HostName:                hostName,
		OwnerID:                 tok.XUID,
		Version:                 protocol.CurrentVersion,
		WorldName:               worldName,
		WorldType:               m.viewership.WorldType,
		Protocol:                protocol.CurrentProtocol,
		MemberCount:             m.viewership.MemberCount,
		MaxMemberCount:          m.viewership.MaxMemberCount,
		BroadcastSetting:        m.viewership.BroadcastSetting,
		LanGame:                 m.viewership.LanGame,
		OnlineCrossPlatformGame: m.viewership.OnlineCrossPlatformGame,
		CrossPlayDisabled:       m.viewership.CrossPlayDisabled,
	}

	meta := m.metadataFor(acct)
	status.LevelID = meta.levelID

	titleID, err := strconv.ParseInt(xbox.TitleID, 10, 64)
	if err != nil {
		return room.Status{}, fmt.Errorf("parse title id: %w", err)
	}
	status.TitleID = titleID

	if m.listener != nil {
		port, guid := m.listenerInfo()
		if port != 0 {
			status.SupportedConnections = append(status.SupportedConnections, room.Connection{
				ConnectionType: room.ConnectionTypeUPNP,
				HostPort:       port,
				RakNetGUID:     guid,
			})
			if status.TransportLayer == 0 {
				status.TransportLayer = room.TransportLayerRakNet
			}
			if status.RakNetGUID == "" {
				status.RakNetGUID = guid
			}
		}
	}

	if m.nether != nil {
		netherID, err := m.nether.NetworkID(ctx, acct)
		if err != nil {
			return room.Status{}, fmt.Errorf("nether network id: %w", err)
		}
		if netherID != 0 {
			status.TransportLayer = room.TransportLayerNetherNet
			status.SupportedConnections = append(status.SupportedConnections, room.Connection{
				ConnectionType: room.ConnectionTypeWebSocketsWebRTCSignaling,
				NetherNetID:    netherID,
			})
		}
	}

	if len(status.SupportedConnections) == 0 {
		status.TransportLayer = room.TransportLayerNetherNet
	}
	return status, nil
}

func (m *Server) listenerInfo() (uint16, string) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.listenPort, m.listenGUID
}

func (m *Server) metadataFor(acct *xbox.Account) *statusMetadata {
	id := acct.SessionID()
	m.mu.Lock()
	defer m.mu.Unlock()
	meta, ok := m.statusMeta[id]
	if !ok {
		meta = &statusMetadata{levelID: randomLevelID()}
		m.statusMeta[id] = meta
	}
	return meta
}

func randomLevelID() string {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return base64.StdEncoding.EncodeToString([]byte("console"))
	}
	return base64.StdEncoding.EncodeToString(buf)
}

func (m *Server) refreshSessions(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.accounts.WithAccounts(func(acct *xbox.Account) {
				if err := m.ensureSession(ctx, acct); err != nil {
					m.log.Printf("refresh session failed for %s: %v", acct.Gamertag(), err)
				}
			})
		}
	}
}

func (m *Server) Listen(ctx context.Context, opts Options) error {
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
	m.captureListenerInfo(listener)
	if m.nether != nil {
		go m.listenNether(ctx, opts.Provider)
	}
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
			m.log.Printf("accept connection failed: %v", err)
			continue
		}

		minecraftConn := conn.(*minecraft.Conn)
		go func() {
			select {
			case <-ctx.Done():
				return
			case <-minecraftConn.Context().Done():
				m.log.Printf("main connection lost, attempting immediate reconnection")
				time.Sleep(500 * time.Millisecond)
				return
			}
		}()
		go m.handleConn(ctx, minecraftConn)
	}
}

func (m *Server) captureListenerInfo(listener *minecraft.Listener) {
	if listener == nil {
		return
	}
	var port uint16
	if addr, ok := listener.Addr().(*net.UDPAddr); ok {
		port = uint16(addr.Port)
	}
	guid := m.listenGUID
	if guid == "" {
		guid = strings.ReplaceAll(uuid.NewString(), "-", "")
	}
	m.mu.Lock()
	m.listenPort = port
	m.listenGUID = guid
	m.mu.Unlock()

	go m.accounts.WithAccounts(func(acct *xbox.Account) {
		if err := m.ensureSession(context.Background(), acct); err != nil {
			m.log.Printf("update session failed for %s: %v", acct.Gamertag(), err)
		}
	})
}

func (m *Server) listenNether(ctx context.Context, provider minecraft.ServerStatusProvider) {
	if m.accounts == nil || m.nether == nil {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	m.setNetherRuntime(ctx, provider)
	m.accounts.WithAccounts(func(acct *xbox.Account) {
		m.startNetherForAccount(ctx, provider, acct)
	})
}

func (m *Server) listenNetherForAccount(ctx context.Context, provider minecraft.ServerStatusProvider, acct *xbox.Account) {
	if acct == nil || m.nether == nil {
		return
	}
	networkName := m.nether.NetworkName(acct)
	if networkName == "" {
		networkName = fmt.Sprintf("nethernet:%s", acct.SessionID())
	}

	if ctx.Err() != nil {
		return
	}
	sig, done, err := m.nether.WaitSignaling(ctx, acct)
	if err != nil {
		if ctx.Err() != nil || errors.Is(err, context.Canceled) {
			return
		}
		m.log.Printf("wait nether signaling failed for %s: %v", acct.Gamertag(), err)
		return
	}
	if sig == nil {
		return
	}

	doneCh := done
	if doneCh == nil {
		doneCh = ctx.Done()
	}

	m.nether.RegisterNetwork(networkName, func(l *slog.Logger) minecraft.Network {
		if l == nil {
			l = slog.New(slog.NewTextHandler(os.Stdout, nil))
		}
		return minecraft.NetherNet{
			Signaling: sig,
			ListenConfig: nethernet.ListenConfig{
				Log: l,
			},
		}
	})

	listener, err := minecraft.ListenConfig{
		StatusProvider: provider,
		PacketFunc:     m.handlePackets,
	}.Listen(networkName, "")
	if err != nil {
		m.log.Printf("listen nether failed for %s: %v", acct.Gamertag(), err)
		return
	}

	acceptCtx, cancel := context.WithCancel(ctx)
	go func() {
		select {
		case <-doneCh:
		case <-ctx.Done():
		}
		cancel()
		_ = listener.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) || acceptCtx.Err() != nil {
				break
			}
			m.log.Printf("accept nether connection failed: %v", err)
			continue
		}

		netherConn := conn.(*minecraft.Conn)
		go func() {
			select {
			case <-acceptCtx.Done():
				return
			case <-netherConn.Context().Done():
				m.log.Printf("nether connection lost, attempting immediate reconnection")
				time.Sleep(500 * time.Millisecond)
				return
			}
		}()
		go m.handleConn(acceptCtx, netherConn)
	}

	cancel()
	_ = listener.Close()
}

func (m *Server) handleConn(ctx context.Context, conn *minecraft.Conn) {
	addr := conn.RemoteAddr().String()
	m.mu.Lock()
	m.conns[addr] = conn
	m.mu.Unlock()
	defer m.CloseClient(addr)

	requireFlag := m.relay.RemoteAddress != "" && m.nether != nil

	var host *xbox.Account
	if requireFlag {
		var err error
		host, err = m.waitForTransferFlag(ctx)
		if host == nil {
			if ctx.Err() != nil || errors.Is(err, context.Canceled) {
				return
			}
			if errors.Is(err, context.DeadlineExceeded) {
				m.log.Printf("timed out waiting for transfer flag: %s", addr)
			} else {
				m.log.Printf("no pending transfer available: %s", addr)
			}
			m.notifyNoPendingTransfer(conn)
			return
		}
	}

	subs := m.trackClient(addr, host, conn)
	if subs != nil && requireFlag {
		subs.SetMetadata("transferFlagged", true)
	}

	gameData := m.gameDataFor(host)

	if err := conn.StartGame(gameData); err != nil {
		m.log.Printf("start game failed: %v", err)
		return
	}

	clientData := conn.ClientData()
	identity := conn.IdentityData()
	if subs != nil {
		if name := clientData.ThirdPartyName; name != "" {
			subs.SetMetadata("clientGamertag", name)
		}
		if identity.XUID != "" {
			subs.SetMetadata("clientXUID", identity.XUID)
		}
	}

	if m.relay.RemoteAddress != "" {
		clientName := clientData.ThirdPartyName
		if clientName == "" {
			clientName = identity.DisplayName
		}
		if host != nil {
			m.log.Printf("transferring client %s to %s (host: %s)", clientName, m.relay.RemoteAddress, host.Gamertag())
		} else {
			m.log.Printf("transferring client %s to %s", clientName, m.relay.RemoteAddress)
		}
		if err := m.transferClient(ctx, conn); err != nil {
			m.log.Printf("relay transfer failed: %v", err)
			m.notifyTransferFailure(conn, err)
		}
		return
	}

	select {
	case <-ctx.Done():
		return
	case <-conn.Context().Done():
		m.log.Printf("connection lost for %s, initiating reconnection", addr)
		go m.reconnectClient(addr, host)
		return
	}
}

func (m *Server) reconnectClient(addr string, host *xbox.Account) {
	if m.nether == nil {
		return
	}

	ctx := m.sessionContext()
	reconnectCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	for {
		select {
		case <-reconnectCtx.Done():
			m.log.Printf("reconnection timeout for %s", addr)
			return
		default:
		}

		if err := m.ensureSession(reconnectCtx, host); err != nil {
			m.log.Printf("reconnection session failed for %s: %v", addr, err)
			time.Sleep(2 * time.Second)
			continue
		}

		m.log.Printf("reconnection successful for %s", addr)
		return
	}
}

func (m *Server) waitForTransferFlag(ctx context.Context) (*xbox.Account, error) {
	if m.nether == nil {
		return nil, nil
	}
	waitCtx, cancel := context.WithTimeout(ctx, transferFlagTimeout)
	defer cancel()
	acct := m.nether.ClaimPending(waitCtx)
	if acct != nil {
		return acct, nil
	}
	return nil, waitCtx.Err()
}

func (m *Server) notifyNoPendingTransfer(conn *minecraft.Conn) {
	if conn == nil {
		return
	}
	_ = conn.WritePacket(&packet.Disconnect{
		Reason:  packet.DisconnectReasonKicked,
		Message: "Unable to join: Host not ready. Please try again shortly.",
	})
	_ = conn.Flush()
}

func (m *Server) gameDataFor(acct *xbox.Account) minecraft.GameData {
	runtimeID := m.entityIDs.Add(1)
	worldName := defaultWorldName("")
	if acct != nil {
		worldName = defaultWorldName(acct.Gamertag())
	}
	const spawnY = 64
	return minecraft.GameData{
		WorldName:                    worldName,
		BaseGameVersion:              protocol.CurrentVersion,
		Difficulty:                   2,
		EntityUniqueID:               int64(runtimeID),
		EntityRuntimeID:              runtimeID,
		PlayerGameMode:               0,
		WorldGameMode:                0,
		PlayerPosition:               mgl32.Vec3{0, float32(spawnY), 0},
		WorldSpawn:                   protocol.BlockPos{0, int32(spawnY), 0},
		Dimension:                    packet.DimensionOverworld,
		GamePublishSetting:           2,
		Time:                         0,
		ChunkRadius:                  8,
		PlayerPermissions:            1,
		ServerAuthoritativeInventory: true,
	}
}

func (m *Server) handlePackets(header packet.Header, payload []byte, src net.Addr, dst net.Addr) {
	subs := m.lookupClient(src.String())
	if subs == nil {
		return
	}
	subs.UpdateLastPing()
}

func (m *Server) lookupClient(addr string) *ClientSession {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.subsessions[addr]
}

func (m *Server) trackClient(addr string, acct *xbox.Account, conn *minecraft.Conn) *ClientSession {
	subs := &ClientSession{Account: acct, Conn: conn, LastPing: time.Now(), Metadata: map[string]any{}}
	m.mu.Lock()
	m.subsessions[addr] = subs
	m.mu.Unlock()
	return subs
}

func (m *Server) CloseClient(addr string) {
	m.mu.Lock()
	if conn, ok := m.conns[addr]; ok {
		conn.Close()
		delete(m.conns, addr)
	}
	delete(m.subsessions, addr)
	m.mu.Unlock()
}

func (m *Server) transferClient(ctx context.Context, conn *minecraft.Conn) error {
	host, portStr, err := net.SplitHostPort(m.relay.RemoteAddress)
	if err != nil {
		return fmt.Errorf("invalid relay address: %w", err)
	}

	timeout := m.relay.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	if err := m.verifyRelayTarget(ctx, timeout); err != nil {
		return err
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return fmt.Errorf("parse relay port: %w", err)
	}

	if err := conn.WritePacket(&packet.Transfer{Address: host, Port: uint16(port)}); err != nil {
		return fmt.Errorf("send transfer packet: %w", err)
	}
	if err := conn.Flush(); err != nil {
		return fmt.Errorf("flush transfer packet: %w", err)
	}
	select {
	case <-ctx.Done():
	case <-time.After(2 * time.Second):
	}
	return nil
}

func (m *Server) notifyTransferFailure(conn *minecraft.Conn, relayErr error) {
	msg := fmt.Sprintf("Unable to reach the relay destination: %v", relayErr)
	_ = conn.WritePacket(&packet.Disconnect{
		Reason:  packet.DisconnectReasonKicked,
		Message: msg,
	})
}

const (
	relayCheckInterval  = 15 * time.Second
	transferFlagTimeout = 20 * time.Second
)

func (m *Server) verifyRelayTarget(ctx context.Context, timeout time.Duration) error {
	if m.relay.RemoteAddress == "" || !m.relay.VerifyTarget {
		return nil
	}

	m.relayCheck.mu.Lock()
	if !m.relayCheck.lastCheck.IsZero() && time.Since(m.relayCheck.lastCheck) < relayCheckInterval {
		cachedErr := m.relayCheck.err
		m.relayCheck.mu.Unlock()
		return cachedErr
	}
	m.relayCheck.mu.Unlock()

	_, err := raknet.Ping(m.relay.RemoteAddress)
	if err != nil {
		err = fmt.Errorf("ping relay target %s: %w", m.relay.RemoteAddress, err)
	}

	m.relayCheck.mu.Lock()
	m.relayCheck.lastCheck = time.Now()
	m.relayCheck.err = err
	m.relayCheck.mu.Unlock()

	return err
}

func (s *ClientSession) UpdateLastPing() {
	s.mu.Lock()
	s.LastPing = time.Now()
	s.mu.Unlock()
}

func (s *ClientSession) SetMetadata(key string, value any) {
	s.mu.Lock()
	if s.Metadata == nil {
		s.Metadata = map[string]any{}
	}
	s.Metadata[key] = value
	s.mu.Unlock()
}

func defaultHostName(gamertag string) string {
	if gamertag == "" {
		return "Console Connect"
	}
	return gamertag
}

func defaultWorldName(gamertag string) string {
	if gamertag == "" {
		return "Minecraft World"
	}
	return fmt.Sprintf("%s Realm", gamertag)
}

type accountTokenSource struct {
	acct *xbox.Account
}

func (s accountTokenSource) Token() (xsapi.Token, error) {
	tok, err := s.acct.Token(context.Background(), xbox.RelyingPartyXboxLive)
	if err != nil {
		return nil, err
	}
	return xsapiToken{tok: tok}, nil
}

type xsapiToken struct {
	tok *xbox.Token
}

func (t xsapiToken) SetAuthHeader(req *http.Request) {
	req.Header.Set("Authorization", t.tok.Header)
}

func (t xsapiToken) String() string {
	return t.tok.Header
}

func (t xsapiToken) DisplayClaims() xsapi.DisplayClaims {
	return xsapi.DisplayClaims{
		GamerTag: t.tok.Gamertag,
		XUID:     t.tok.XUID,
		UserHash: t.tok.UserHash,
	}
}
