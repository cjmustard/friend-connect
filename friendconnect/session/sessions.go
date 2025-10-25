package session

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/df-mc/go-xsapi/mpsd"
	"github.com/google/uuid"
	"github.com/sandertv/gophertunnel/minecraft"
	"github.com/sandertv/gophertunnel/minecraft/protocol"
	"github.com/sandertv/gophertunnel/minecraft/room"

	"github.com/cjmustard/friend-connect/friendconnect/xbox"
)

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

	if err := ann.Announce(ctx, status); err != nil {
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
			ann.Close()
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
	hostName := defaultIfEmpty(m.viewership.HostName, defaultHostName(acct.Gamertag()))
	worldName := defaultIfEmpty(m.viewership.WorldName, defaultWorldName(acct.Gamertag()))

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

	status.LevelID = randomLevelID()

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

func randomLevelID() string {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return base64.StdEncoding.EncodeToString([]byte("console"))
	}
	return base64.StdEncoding.EncodeToString(buf)
}

func (m *Server) refreshSessions(ctx context.Context) {
	ticker := time.NewTicker(sessionRefreshInterval)
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

func defaultIfEmpty(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}
