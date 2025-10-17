package notifications

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/cjmustard/console-connect/minecraft/logger"
)

type Config struct {
	Enabled                  bool   `json:"enabled"`
	WebhookURL               string `json:"webhookUrl"`
	SessionExpiredMessage    string `json:"sessionExpiredMessage"`
	FriendRestrictionMessage string `json:"friendRestrictionMessage"`
}

type Manager interface {
	SendSessionExpired(ctx context.Context, verificationURI, userCode string)
	SendFriendRestriction(ctx context.Context, username, xuid string)
}

type baseManager struct {
	log    *logger.Logger
	config Config
	client *http.Client
}

func NewManager(log *logger.Logger, cfg Config) Manager {
	if !cfg.Enabled || cfg.WebhookURL == "" {
		return &noopManager{}
	}
	return &slackManager{
		baseManager: baseManager{
			log:    log.Prefixed("notify"),
			config: cfg,
			client: &http.Client{Timeout: 5 * time.Second},
		},
	}
}

func (m *baseManager) message(body string) {
	if !m.config.Enabled {
		return
	}
	payload := map[string]string{"text": body}
	encoded, err := json.Marshal(payload)
	if err != nil {
		m.log.Errorf("marshal notification payload: %v", err)
		return
	}
	req, err := http.NewRequest(http.MethodPost, m.config.WebhookURL, bytes.NewReader(encoded))
	if err != nil {
		m.log.Errorf("build notification request: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := m.client.Do(req)
	if err != nil {
		m.log.Errorf("send notification: %v", err)
		return
	}
	resp.Body.Close()
	if resp.StatusCode >= 300 {
		m.log.Errorf("notification webhook returned %s", resp.Status)
	}
}

type slackManager struct {
	baseManager
}

func (m *slackManager) SendSessionExpired(ctx context.Context, verificationURI, userCode string) {
	msg := m.config.SessionExpiredMessage
	if msg == "" {
		msg = "Authenticate at %s using the code %s"
	}
	m.message(fmt.Sprintf(msg, verificationURI, userCode))
}

func (m *slackManager) SendFriendRestriction(ctx context.Context, username, xuid string) {
	msg := m.config.FriendRestrictionMessage
	if msg == "" {
		msg = "Friend restriction detected for %s (%s)"
	}
	m.message(fmt.Sprintf(msg, username, xuid))
}

type noopManager struct{}

func (noopManager) SendSessionExpired(ctx context.Context, verificationURI, userCode string) {}

func (noopManager) SendFriendRestriction(ctx context.Context, username, xuid string) {}
