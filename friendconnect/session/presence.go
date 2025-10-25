package session

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/cjmustard/friend-connect/friendconnect/xbox"
)

func (m *Server) runPresence(ctx context.Context, acct *xbox.Account) {
	for {
		if ctx.Err() != nil {
			return
		}

		delay, err := m.updatePresence(ctx, acct)
		if err != nil {
			m.log.LogSession("presence update failed for %s: %v", acct.Gamertag(), err)
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
		return presenceRetryInterval, err
	}
	tok, err := acct.Token(ctx, xbox.RelyingPartyXboxLive)
	if err != nil {
		return presenceRetryInterval, fmt.Errorf("token: %w", err)
	}
	if tok.XUID == "" {
		return presenceRetryInterval, fmt.Errorf("missing xuid for %s", acct.Gamertag())
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, xbox.UserPresenceURL(tok.XUID), strings.NewReader(`{"state":"active"}`))
	if err != nil {
		return presenceRetryInterval, err
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
