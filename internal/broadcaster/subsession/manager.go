package subsession

import (
	"context"
	"sync"
	"time"

	"github.com/cjmustard/console-connect/internal/broadcaster/logger"
)

type Manager struct {
	log      *logger.Logger
	sessions map[string]*Session
	mu       sync.RWMutex
}

type Session struct {
	ID        string
	Gamertag  string
	Started   time.Time
	LastEvent time.Time
	Metadata  map[string]any
	mu        sync.RWMutex
}

func NewManager(log *logger.Logger) *Manager {
	return &Manager{log: log, sessions: map[string]*Session{}}
}

func (m *Manager) Start(ctx context.Context, id, gamertag string) *Session {
	s := &Session{ID: id, Gamertag: gamertag, Started: time.Now(), LastEvent: time.Now(), Metadata: map[string]any{}}
	m.mu.Lock()
	m.sessions[id] = s
	m.mu.Unlock()
	return s
}

func (m *Manager) End(id string) {
	m.mu.Lock()
	delete(m.sessions, id)
	m.mu.Unlock()
}

func (m *Manager) Snapshot() []Session {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]Session, 0, len(m.sessions))
	for _, s := range m.sessions {
		result = append(result, s.Clone())
	}
	return result
}

func (s *Session) UpdateMetadata(key string, value any) {
	s.mu.Lock()
	if s.Metadata == nil {
		s.Metadata = map[string]any{}
	}
	s.Metadata[key] = value
	s.LastEvent = time.Now()
	s.mu.Unlock()
}

func (s *Session) Clone() Session {
	s.mu.RLock()
	defer s.mu.RUnlock()
	copy := *s
	copy.Metadata = map[string]any{}
	for k, v := range s.Metadata {
		copy.Metadata[k] = v
	}
	return copy
}
