package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/cjmustard/console-connect/internal/broadcaster/notifications"
)

// Config mirrors the structure of the original Java configuration tree but adds Go idioms.
type Config struct {
	XboxClientID     string               `json:"xboxClientId"`
	XboxClientSecret string               `json:"xboxClientSecret"`
	Accounts         []AccountConfig      `json:"accounts"`
	Storage          StorageConfig        `json:"storage"`
	FriendSettings   FriendConfig         `json:"friends"`
	HTTP             HTTPConfig           `json:"http"`
	Ping             PingConfig           `json:"ping"`
	Gallery          GalleryConfig        `json:"gallery"`
	Notifications    notifications.Config `json:"notifications"`
	CustomImages     map[string]string    `json:"customImages"`
}

type AccountConfig struct {
	Gamertag     string   `json:"gamertag"`
	RefreshToken string   `json:"refreshToken"`
	ShowAsOnline bool     `json:"showAsOnline"`
	PreferredIPs []string `json:"preferredIps"`
}

type StorageConfig struct {
	Directory string `json:"directory"`
}

type FriendConfig struct {
	AutoAccept bool          `json:"autoAccept"`
	AutoAdd    bool          `json:"autoAdd"`
	SyncTicker time.Duration `json:"syncTicker"`
}

type HTTPConfig struct {
	Addr         string        `json:"addr"`
	ReadTimeout  time.Duration `json:"readTimeout"`
	WriteTimeout time.Duration `json:"writeTimeout"`
}

type PingConfig struct {
	Enabled bool          `json:"enabled"`
	Target  string        `json:"target"`
	Period  time.Duration `json:"period"`
}

type GalleryConfig struct {
	Enabled bool   `json:"enabled"`
	Path    string `json:"path"`
}

var (
	config     Config
	configLock sync.RWMutex
)

func Load(path string) (Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return Config{}, fmt.Errorf("open config: %w", err)
	}
	defer file.Close()

	dec := json.NewDecoder(file)
	dec.DisallowUnknownFields()
	var cfg Config
	if err := dec.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("decode config: %w", err)
	}

	if cfg.HTTP.Addr == "" {
		cfg.HTTP.Addr = ":8080"
	}
	if cfg.FriendSettings.SyncTicker == 0 {
		cfg.FriendSettings.SyncTicker = time.Minute
	}
	if cfg.Ping.Period == 0 {
		cfg.Ping.Period = 30 * time.Second
	}
	if cfg.Notifications.SessionExpiredMessage == "" {
		cfg.Notifications.SessionExpiredMessage = "Authenticate at %s using the code %s"
	}
	if cfg.Notifications.FriendRestrictionMessage == "" {
		cfg.Notifications.FriendRestrictionMessage = "Friend restriction detected for %s (%s)"
	}

	configLock.Lock()
	config = cfg
	configLock.Unlock()

	return cfg, nil
}

func MustLoad(path string) Config {
	cfg, err := Load(path)
	if err != nil {
		panic(err)
	}
	return cfg
}

func Get() Config {
	configLock.RLock()
	defer configLock.RUnlock()
	return config
}

func Update(mutator func(*Config) error) error {
	configLock.Lock()
	defer configLock.Unlock()

	if config.Accounts == nil {
		return errors.New("configuration not loaded")
	}
	return mutator(&config)
}
