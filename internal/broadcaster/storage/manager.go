package storage

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Manager struct {
	backend *FileBackend
	photo   string
	history *playerHistory
}

func NewManager(dir, screenshotPath string) (*Manager, error) {
	backend, err := NewFileBackend(dir)
	if err != nil {
		return nil, err
	}
	if screenshotPath == "" {
		screenshotPath = filepath.Join(dir, "screenshot.png")
	}
	history, err := newPlayerHistory(filepath.Join(dir, "player_history.json"))
	if err != nil {
		return nil, fmt.Errorf("player history: %w", err)
	}
	return &Manager{backend: backend, photo: screenshotPath, history: history}, nil
}

func (m *Manager) Cache() (string, error) {
	return m.loadRaw("cache")
}

func (m *Manager) SetCache(data string) error {
	return m.saveRaw("cache", data)
}

func (m *Manager) SubSessions() (string, error) {
	return m.loadRaw("sub_sessions")
}

func (m *Manager) SetSubSessions(data string) error {
	return m.saveRaw("sub_sessions", data)
}

func (m *Manager) LastSessionResponse() (string, error) {
	return m.loadRaw("lastSessionResponse")
}

func (m *Manager) SetLastSessionResponse(data string) error {
	return m.saveRaw("lastSessionResponse", data)
}

func (m *Manager) CurrentSessionResponse() (string, error) {
	return m.loadRaw("currentSessionResponse")
}

func (m *Manager) SetCurrentSessionResponse(data string) error {
	return m.saveRaw("currentSessionResponse", data)
}

func (m *Manager) SubSession(id string) (*Manager, error) {
	dir := filepath.Join(m.backend.Dir, id)
	return NewManager(dir, m.photo)
}

func (m *Manager) Screenshot() string {
	return m.photo
}

func (m *Manager) Cleanup() error {
	return os.RemoveAll(m.backend.Dir)
}

func (m *Manager) PlayerHistory() *playerHistory {
	return m.history
}

func (m *Manager) Backend() Backend {
	return m.backend
}

func (m *Manager) loadRaw(key string) (string, error) {
	path := filepath.Join(m.backend.Dir, key+".json")
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return "", nil
	}
	return string(data), err
}

func (m *Manager) saveRaw(key, data string) error {
	path := filepath.Join(m.backend.Dir, key+".json")
	if data == "" {
		return os.Remove(path)
	}
	return os.WriteFile(path, []byte(data), 0o600)
}

type playerHistory struct {
	path string
	mu   sync.Mutex
	data map[string]time.Time
	init bool
}

func newPlayerHistory(path string) (*playerHistory, error) {
	ph := &playerHistory{path: path}
	if err := ph.load(); err != nil {
		return nil, err
	}
	return ph, nil
}

func (p *playerHistory) load() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	raw, err := os.ReadFile(p.path)
	if errors.Is(err, fs.ErrNotExist) {
		p.data = map[string]time.Time{}
		p.init = true
		return nil
	}
	if err != nil {
		return err
	}
	var encoded map[string]int64
	if err := json.Unmarshal(raw, &encoded); err != nil {
		return err
	}
	p.data = make(map[string]time.Time, len(encoded))
	for k, v := range encoded {
		p.data[k] = time.Unix(v, 0).UTC()
	}
	return nil
}

func (p *playerHistory) persist() error {
	encoded := make(map[string]int64, len(p.data))
	for k, v := range p.data {
		encoded[k] = v.Unix()
	}
	raw, err := json.MarshalIndent(encoded, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(p.path, raw, 0o600)
}

func (p *playerHistory) IsFirstRun() bool {
	return p.init
}

func (p *playerHistory) LastSeen(xuid string) (time.Time, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	v, ok := p.data[xuid]
	return v, ok
}

func (p *playerHistory) SetLastSeen(xuid string, t time.Time) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.data == nil {
		p.data = map[string]time.Time{}
	}
	p.data[xuid] = t.UTC()
	return p.persist()
}

func (p *playerHistory) Clear(xuid string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.data, xuid)
	return p.persist()
}

func (p *playerHistory) All() map[string]time.Time {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make(map[string]time.Time, len(p.data))
	for k, v := range p.data {
		out[k] = v
	}
	return out
}
