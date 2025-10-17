package storage

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

type Backend interface {
	Load(key string, value any) error
	Save(key string, value any) error
}

type FileBackend struct {
	Dir string
	mu  sync.Mutex
}

func NewFileBackend(dir string) (*FileBackend, error) {
	if dir == "" {
		return nil, fmt.Errorf("storage directory required")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("create storage dir: %w", err)
	}
	return &FileBackend{Dir: dir}, nil
}

func (f *FileBackend) Load(key string, value any) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	path := filepath.Join(f.Dir, key+".json")
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("open storage file: %w", err)
	}
	defer file.Close()
	return json.NewDecoder(file).Decode(value)
}

func (f *FileBackend) Save(key string, value any) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	path := filepath.Join(f.Dir, key+".json")
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create storage file: %w", err)
	}
	defer file.Close()
	enc := json.NewEncoder(file)
	enc.SetIndent("", "  ")
	return enc.Encode(value)
}
