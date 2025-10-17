package gallery

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
)

type Manager struct {
	path string
	mu   sync.RWMutex
}

func New(path string) (*Manager, error) {
	if path == "" {
		return nil, errors.New("gallery path required")
	}
	if err := os.MkdirAll(path, 0o755); err != nil {
		return nil, err
	}
	return &Manager{path: path}, nil
}

func (m *Manager) Save(name string, r io.Reader) error {
	if name == "" {
		return errors.New("image name required")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	file, err := os.Create(filepath.Join(m.path, name))
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = io.Copy(file, r)
	return err
}

func (m *Manager) Open(name string) (io.ReadCloser, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return os.Open(filepath.Join(m.path, name))
}
