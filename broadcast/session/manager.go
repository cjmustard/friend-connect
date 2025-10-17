package session

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/sandertv/gophertunnel/minecraft"
	"github.com/sandertv/gophertunnel/minecraft/protocol/packet"

	"github.com/cjmustard/consoleconnect/broadcast/account"
	"github.com/cjmustard/consoleconnect/broadcast/logger"
)

type Manager struct {
	log         *logger.Logger
	accounts    *account.Manager
	listener    *minecraft.Listener
	conns       map[string]*minecraft.Conn
	connMu      sync.RWMutex
	subsessions map[string]*SubSession
	subsMu      sync.RWMutex
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

func NewManager(log *logger.Logger, accounts *account.Manager) *Manager {
	return &Manager{
		log:         log,
		accounts:    accounts,
		conns:       map[string]*minecraft.Conn{},
		subsessions: map[string]*SubSession{},
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
