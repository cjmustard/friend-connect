package session

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
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

	"github.com/cjmustard/consoleconnect/broadcast/account"
	"github.com/cjmustard/consoleconnect/broadcast/constants"
	"github.com/cjmustard/consoleconnect/broadcast/logger"
	"github.com/cjmustard/consoleconnect/broadcast/nether"
	"github.com/cjmustard/consoleconnect/broadcast/xbox"
)

type Manager struct {
	log      *logger.Logger
	accounts *account.Manager
	listener *minecraft.Listener

	conns  map[string]*minecraft.Conn
	connMu sync.RWMutex

	subsessions map[string]*SubSession
	subsMu      sync.RWMutex

	httpClient *http.Client
	nether     *nether.Manager

	announcers map[string]*room.XBLAnnouncer
	sessions   map[string]*mpsd.Session
	sessMu     sync.RWMutex

	listenMu   sync.RWMutex
	listenPort uint16
	listenGUID string

	statusMeta map[string]*statusMetadata
	metaMu     sync.Mutex

	relay RelayOptions

	relayCheck relayCheckState

	entityIDs atomic.Uint64

	ctx   context.Context
	ctxMu sync.RWMutex

	startedMu       sync.Mutex
	startedAccounts map[string]struct{}

	netherMu       sync.RWMutex
	netherProvider minecraft.ServerStatusProvider
	netherCtx      context.Context
	netherAccounts map[string]struct{}
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

type statusMetadata struct {
	levelID string
}

type RelayOptions struct {
	RemoteAddress string
	VerifyTarget  bool
	Timeout       time.Duration
}

type relayCheckState struct {
	mu        sync.Mutex
	lastCheck time.Time
	err       error
}

func NewManager(log *logger.Logger, accounts *account.Manager, netherMgr *nether.Manager, httpClient *http.Client) *Manager {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}
	return &Manager{
		log:             log,
		accounts:        accounts,
		conns:           map[string]*minecraft.Conn{},
		subsessions:     map[string]*SubSession{},
		httpClient:      httpClient,
		nether:          netherMgr,
		announcers:      map[string]*room.XBLAnnouncer{},
		sessions:        map[string]*mpsd.Session{},
		statusMeta:      map[string]*statusMetadata{},
		startedAccounts: map[string]struct{}{},
		netherAccounts:  map[string]struct{}{},
	}
}

func (m *Manager) ConfigureRelay(opts RelayOptions) {
	if opts.Timeout <= 0 {
		opts.Timeout = 5 * time.Second
	}
	m.relay = opts
}

func (m *Manager) Start(ctx context.Context) {
	if ctx == nil {
		ctx = context.Background()
	}
	m.setContext(ctx)
	m.accounts.WithAccounts(func(acct *account.Account) {
		m.startAccount(acct)
	})
	go m.refreshSessions(ctx)
}

func (m *Manager) setContext(ctx context.Context) {
	m.ctxMu.Lock()
	m.ctx = ctx
	m.ctxMu.Unlock()
}

func (m *Manager) sessionContext() context.Context {
	m.ctxMu.RLock()
	ctx := m.ctx
	m.ctxMu.RUnlock()
	if ctx == nil {
		return context.Background()
	}
	return ctx
}

func (m *Manager) startAccount(acct *account.Account) {
	if acct == nil {
		return
	}
	id := acct.SessionID()
	m.startedMu.Lock()
	if _, ok := m.startedAccounts[id]; ok {
		m.startedMu.Unlock()
		return
	}
	m.startedAccounts[id] = struct{}{}
	m.startedMu.Unlock()

	ctx := m.sessionContext()
	go func() {
		if err := m.ensureSession(ctx, acct); err != nil {
			m.log.Errorf("create session for %s: %v", acct.Gamertag(), err)
		}
	}()
	if acct.ShowAsOnline() {
		go m.runPresence(ctx, acct)
	}
}

func (m *Manager) AttachAccount(ctx context.Context, acct *account.Account) {
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

func (m *Manager) setNetherRuntime(ctx context.Context, provider minecraft.ServerStatusProvider) {
	m.netherMu.Lock()
	m.netherCtx = ctx
	m.netherProvider = provider
	m.netherMu.Unlock()
}

func (m *Manager) netherRuntime() (minecraft.ServerStatusProvider, context.Context) {
	m.netherMu.RLock()
	provider := m.netherProvider
	ctx := m.netherCtx
	m.netherMu.RUnlock()
	return provider, ctx
}

func (m *Manager) startNetherForAccount(ctx context.Context, provider minecraft.ServerStatusProvider, acct *account.Account) {
	if acct == nil || provider == nil || m.nether == nil {
		return
	}
	if ctx == nil {
		ctx = m.sessionContext()
	}
	id := acct.SessionID()
	m.netherMu.Lock()
	if _, ok := m.netherAccounts[id]; ok {
		m.netherMu.Unlock()
		return
	}
	m.netherAccounts[id] = struct{}{}
	m.netherMu.Unlock()
	go m.listenNetherForAccount(ctx, provider, acct)
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
	if acct == nil {
		return errors.New("nil account")
	}
	tok, err := acct.Token(ctx, constants.RelyingPartyXboxLive)
	if err != nil {
		return fmt.Errorf("token: %w", err)
	}
	status, err := m.buildStatus(ctx, acct, tok)
	if err != nil {
		return err
	}
	ann := m.announcerFor(acct)
	if err := ann.Announce(ctx, status); err != nil {
		return fmt.Errorf("announce session: %w", err)
	}
	if ann.Session != nil {
		m.storeSession(acct.SessionID(), ann.Session)
	}
	return nil
}

func (m *Manager) announcerFor(acct *account.Account) *room.XBLAnnouncer {
	sessionID := acct.SessionID()
	m.sessMu.Lock()
	defer m.sessMu.Unlock()
	if ann, ok := m.announcers[sessionID]; ok {
		return ann
	}
	scid := uuid.MustParse(constants.ServiceConfigID)
	ann := &room.XBLAnnouncer{
		TokenSource: xboxTokenSource{acct: acct},
		SessionReference: mpsd.SessionReference{
			ServiceConfigID: scid,
			TemplateName:    constants.TemplateName,
			Name:            strings.ToUpper(sessionID),
		},
		PublishConfig: mpsd.PublishConfig{Client: m.httpClient},
	}
	m.announcers[sessionID] = ann
	return ann
}

func (m *Manager) storeSession(id string, sess *mpsd.Session) {
	if sess == nil || id == "" {
		return
	}
	m.sessMu.Lock()
	m.sessions[id] = sess
	m.sessMu.Unlock()
}

func (m *Manager) sessionFor(acct *account.Account) *mpsd.Session {
	if acct == nil {
		return nil
	}
	m.sessMu.RLock()
	defer m.sessMu.RUnlock()
	return m.sessions[acct.SessionID()]
}

func (m *Manager) buildStatus(ctx context.Context, acct *account.Account, tok *xbox.Token) (room.Status, error) {
	status := room.Status{
		Joinability:             room.JoinabilityJoinableByFriends,
		HostName:                defaultHostName(acct.Gamertag()),
		OwnerID:                 tok.XUID,
		Version:                 protocol.CurrentVersion,
		WorldName:               defaultWorldName(acct.Gamertag()),
		WorldType:               "Survival",
		Protocol:                protocol.CurrentProtocol,
		MemberCount:             1,
		MaxMemberCount:          8,
		BroadcastSetting:        room.BroadcastSettingFriendsOfFriends,
		LanGame:                 false,
		OnlineCrossPlatformGame: true,
		CrossPlayDisabled:       false,
	}

	meta := m.metadataFor(acct)
	status.LevelID = meta.levelID

	titleID, err := strconv.ParseInt(constants.TitleID, 10, 64)
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

func (m *Manager) listenerInfo() (uint16, string) {
	m.listenMu.RLock()
	defer m.listenMu.RUnlock()
	return m.listenPort, m.listenGUID
}

func (m *Manager) metadataFor(acct *account.Account) *statusMetadata {
	id := acct.SessionID()
	m.metaMu.Lock()
	defer m.metaMu.Unlock()
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
			m.log.Errorf("accept connection: %v", err)
			continue
		}
		m.log.Debugf("client connected: %s", conn.RemoteAddr())
		go m.handleConn(ctx, conn.(*minecraft.Conn))
	}
}

func (m *Manager) captureListenerInfo(listener *minecraft.Listener) {
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
	m.listenMu.Lock()
	m.listenPort = port
	m.listenGUID = guid
	m.listenMu.Unlock()

	go m.accounts.WithAccounts(func(acct *account.Account) {
		if err := m.ensureSession(context.Background(), acct); err != nil {
			m.log.Errorf("update session for %s: %v", acct.Gamertag(), err)
		}
	})
}

func (m *Manager) listenNether(ctx context.Context, provider minecraft.ServerStatusProvider) {
	if m.accounts == nil || m.nether == nil {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	m.setNetherRuntime(ctx, provider)
	m.accounts.WithAccounts(func(acct *account.Account) {
		m.startNetherForAccount(ctx, provider, acct)
	})
}

func (m *Manager) listenNetherForAccount(ctx context.Context, provider minecraft.ServerStatusProvider, acct *account.Account) {
	if acct == nil || m.nether == nil {
		return
	}
	networkName := m.nether.NetworkName(acct)
	if networkName == "" {
		networkName = fmt.Sprintf("nethernet:%s", acct.SessionID())
	}

	for {
		if ctx.Err() != nil {
			return
		}
		sig, done, err := m.nether.WaitSignaling(ctx, acct)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, context.Canceled) {
				return
			}
			m.log.Errorf("wait nether signaling for %s: %v", acct.Gamertag(), err)
			time.Sleep(time.Second)
			continue
		}
		if sig == nil {
			continue
		}

		doneCh := done
		if doneCh == nil {
			doneCh = ctx.Done()
		}

		m.nether.RegisterNetwork(networkName, func(l *slog.Logger) minecraft.Network {
			if l == nil {
				l = slog.Default()
			}
			l = l.With(slog.String("network", networkName))
			if acct != nil {
				l = l.With(slog.String("gamertag", acct.Gamertag()))
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
			m.log.Errorf("listen nether for %s: %v", acct.Gamertag(), err)
			select {
			case <-ctx.Done():
				return
			case <-doneCh:
			}
			continue
		}

		m.log.Infof("nether listener ready for %s (network %d)", acct.Gamertag(), sig.NetworkID())

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
				m.log.Errorf("accept nether connection: %v", err)
				continue
			}
			m.log.Debugf("nether client connected: %s", conn.RemoteAddr())
			go m.handleConn(acceptCtx, conn.(*minecraft.Conn))
		}

		cancel()
		_ = listener.Close()

		select {
		case <-ctx.Done():
			return
		case <-doneCh:
			m.log.Warnf("nether listener for %s stopped, awaiting reconnection", acct.Gamertag())
		}
	}
}

func (m *Manager) handleConn(ctx context.Context, conn *minecraft.Conn) {
	addr := conn.RemoteAddr().String()
	m.connMu.Lock()
	m.conns[addr] = conn
	m.connMu.Unlock()
	defer m.Close(addr)

	requireFlag := m.relay.RemoteAddress != "" && m.nether != nil

	var host *account.Account
	if requireFlag {
		var err error
		host, err = m.waitForTransferFlag(ctx)
		if host == nil {
			if ctx.Err() != nil || errors.Is(err, context.Canceled) {
				return
			}
			if errors.Is(err, context.DeadlineExceeded) {
				m.log.Warnf("timed out waiting for transfer flag for %s", addr)
			} else {
				m.log.Warnf("no pending transfer available for %s", addr)
			}
			m.notifyNoPendingTransfer(conn)
			return
		}
	}

	subs := m.RegisterSubSession(addr, host, conn)
	if subs != nil && requireFlag {
		subs.SetMetadata("transferFlagged", true)
	}

	gameData := m.gameDataFor(host)
	if requireFlag {
		if enriched, err := m.enrichGameData(ctx, conn, host, gameData); err != nil {
			m.log.Warnf("load remote game data: %v", err)
		} else {
			gameData = enriched
		}
	}

	if err := conn.StartGame(gameData); err != nil {
		m.log.Errorf("start game: %v", err)
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
			m.log.Infof("transferring %s to %s for %s", clientName, m.relay.RemoteAddress, host.Gamertag())
		} else {
			m.log.Infof("transferring %s to %s", clientName, m.relay.RemoteAddress)
		}
		if err := m.transferClient(ctx, conn); err != nil {
			m.log.Errorf("relay transfer: %v", err)
			m.notifyTransferFailure(conn, err)
		}
		return
	}

	<-ctx.Done()
}

func (m *Manager) waitForTransferFlag(ctx context.Context) (*account.Account, error) {
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

func (m *Manager) notifyNoPendingTransfer(conn *minecraft.Conn) {
	if conn == nil {
		return
	}
	_ = conn.WritePacket(&packet.Disconnect{
		Reason:  packet.DisconnectReasonKicked,
		Message: "Unable to join: Host not ready. Please try again shortly.",
	})
	_ = conn.Flush()
}

func (m *Manager) gameDataFor(acct *account.Account) minecraft.GameData {
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
			entry["gamertag"] = subs.Account.Gamertag()
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

func (m *Manager) transferClient(ctx context.Context, conn *minecraft.Conn) error {
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
	// Allow ample time for clients to process the transfer and tear down their
	// RakNet connection themselves before the listener forces the close.
	select {
	case <-ctx.Done():
	case <-time.After(2 * time.Second):
	}
	return nil
}

func (m *Manager) notifyTransferFailure(conn *minecraft.Conn, relayErr error) {
	msg := fmt.Sprintf("Unable to reach the relay destination: %v", relayErr)
	_ = conn.WritePacket(&packet.Disconnect{
		Reason:  packet.DisconnectReasonKicked,
		Message: msg,
	})
}

const (
	relayCheckInterval    = 15 * time.Second
	transferFlagTimeout   = 20 * time.Second
	remoteGameDataTimeout = 15 * time.Second
)

func (m *Manager) enrichGameData(ctx context.Context, conn *minecraft.Conn, host *account.Account, base minecraft.GameData) (minecraft.GameData, error) {
	if m.relay.RemoteAddress == "" {
		return base, errors.New("relay remote address not configured")
	}
	if m.nether == nil {
		return base, errors.New("nether manager unavailable")
	}
	src := m.nether.TokenSource(host)
	if src == nil {
		return base, errors.New("missing authentication for host")
	}

	timeout := m.relay.Timeout
	if timeout <= 0 {
		timeout = remoteGameDataTimeout
	}

	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	dialer := minecraft.Dialer{
		TokenSource: src,
		ClientData:  conn.ClientData(),
	}
	serverConn, err := dialer.DialContext(dialCtx, "raknet", m.relay.RemoteAddress)
	if err != nil {
		return base, fmt.Errorf("dial remote: %w", err)
	}
	defer serverConn.Close()

	remote := serverConn.GameData()
	if len(remote.Items) == 0 && len(remote.CustomBlocks) == 0 {
		return base, fmt.Errorf("remote game data incomplete")
	}

	remote.EntityRuntimeID = base.EntityRuntimeID
	remote.EntityUniqueID = base.EntityUniqueID
	remote.PlayerPermissions = base.PlayerPermissions
	remote.PlayerGameMode = base.PlayerGameMode
	remote.WorldGameMode = base.WorldGameMode
	remote.PlayerPosition = base.PlayerPosition
	remote.WorldSpawn = base.WorldSpawn
	if remote.WorldName == "" {
		remote.WorldName = base.WorldName
	}
	if remote.BaseGameVersion == "" {
		remote.BaseGameVersion = base.BaseGameVersion
	}
	if remote.ChunkRadius == 0 {
		remote.ChunkRadius = base.ChunkRadius
	}

	return remote, nil
}

func (m *Manager) verifyRelayTarget(ctx context.Context, timeout time.Duration) error {
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

	pingCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	result := make(chan error, 1)
	go func(addr string) {
		_, err := raknet.Ping(addr)
		result <- err
	}(m.relay.RemoteAddress)

	var err error
	select {
	case err = <-result:
	case <-pingCtx.Done():
		err = pingCtx.Err()
	}

	if err != nil {
		err = fmt.Errorf("ping relay target %s: %w", m.relay.RemoteAddress, err)
	} else {
		m.log.Debugf("relay target %s reachable", m.relay.RemoteAddress)
	}

	m.relayCheck.mu.Lock()
	m.relayCheck.lastCheck = time.Now()
	m.relayCheck.err = err
	m.relayCheck.mu.Unlock()

	return err
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
	snapshot := map[string]any{
		"lastPing": s.LastPing,
	}
	for k, v := range s.Metadata {
		snapshot[k] = v
	}
	return snapshot
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

type xboxTokenSource struct {
	acct *account.Account
}

func (s xboxTokenSource) Token() (xsapi.Token, error) {
	tok, err := s.acct.Token(context.Background(), constants.RelyingPartyXboxLive)
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
