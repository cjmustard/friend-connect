package friends

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/cjmustard/consoleconnect/broadcast/account"
	"github.com/cjmustard/consoleconnect/broadcast/constants"
	"github.com/cjmustard/consoleconnect/broadcast/xbox"
)

type XboxProvider struct {
	client *http.Client
}

func NewXboxProvider(client *http.Client) *XboxProvider {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &XboxProvider{client: client}
}

func (p *XboxProvider) ListFriends(ctx context.Context, acct *account.Account) ([]Friend, error) {
	token, err := acct.Token(ctx, constants.RelyingPartyXboxLive)
	if err != nil {
		return nil, fmt.Errorf("fetch token: %w", err)
	}

	followers, err := p.fetchPeople(ctx, constants.FollowersURL, token)
	if err != nil {
		return nil, err
	}
	social, err := p.fetchPeople(ctx, constants.SocialURL, token)
	if err != nil {
		return nil, err
	}

	merged := map[string]person{}
	for _, entry := range append(followers, social...) {
		if existing, ok := merged[entry.XUID]; ok {
			merged[entry.XUID] = mergePerson(existing, entry)
		} else {
			merged[entry.XUID] = entry
		}
	}

	friends := make([]Friend, 0, len(merged))
	for _, entry := range merged {
		name := entry.Gamertag
		if name == "" {
			name = entry.DisplayName
		}
		friends = append(friends, Friend{
			Gamertag: name,
			Added:    entry.AddedTime(),
			Online:   strings.EqualFold(entry.PresenceState, "Online"),
		})
	}
	return friends, nil
}

func (p *XboxProvider) AddFriend(ctx context.Context, acct *account.Account, gamertag string) error {
	if gamertag == "" {
		return fmt.Errorf("missing gamertag")
	}
	token, err := acct.Token(ctx, constants.RelyingPartyXboxLive)
	if err != nil {
		return fmt.Errorf("fetch token: %w", err)
	}
	xuid, err := p.lookupXUID(ctx, token, gamertag)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, constants.PeopleURL(xuid), nil)
	if err != nil {
		return err
	}
	applyCommonHeaders(req, token)
	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("add friend request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("add friend %s (%s): status %d: %s", gamertag, xuid, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

func (p *XboxProvider) RemoveFriend(ctx context.Context, acct *account.Account, gamertag string) error {
	if gamertag == "" {
		return fmt.Errorf("missing gamertag")
	}
	token, err := acct.Token(ctx, constants.RelyingPartyXboxLive)
	if err != nil {
		return fmt.Errorf("fetch token: %w", err)
	}
	xuid, err := p.lookupXUID(ctx, token, gamertag)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, constants.PeopleURL(xuid), nil)
	if err != nil {
		return err
	}
	applyCommonHeaders(req, token)
	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("remove friend request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("remove friend %s (%s): status %d: %s", gamertag, xuid, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

func (p *XboxProvider) fetchPeople(ctx context.Context, endpoint string, token *xbox.Token) ([]person, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	applyCommonHeaders(req, token)
	req.Header.Set("x-xbl-contract-version", "5")
	req.Header.Set("accept-language", "en-GB")

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", endpoint, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return nil, fmt.Errorf("fetch %s: status %d: %s", endpoint, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var out struct {
		People []person `json:"people"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode %s response: %w", endpoint, err)
	}
	return out.People, nil
}

func (p *XboxProvider) lookupXUID(ctx context.Context, token *xbox.Token, gamertag string) (string, error) {
	endpoint := fmt.Sprintf("https://profile.xboxlive.com/users/gt(%s)/profile/settings?settings=Gamertag", url.PathEscape(gamertag))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", err
	}
	applyCommonHeaders(req, token)
	req.Header.Set("x-xbl-contract-version", "2")

	resp, err := p.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("resolve gamertag: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return "", fmt.Errorf("resolve gamertag %s: status %d: %s", gamertag, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var out struct {
		ProfileUsers []struct {
			ID string `json:"id"`
		} `json:"profileUsers"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", fmt.Errorf("decode profile for %s: %w", gamertag, err)
	}
	if len(out.ProfileUsers) == 0 || out.ProfileUsers[0].ID == "" {
		return "", fmt.Errorf("gamertag %s not found", gamertag)
	}
	return out.ProfileUsers[0].ID, nil
}

func applyCommonHeaders(req *http.Request, token *xbox.Token) {
	req.Header.Set("Authorization", token.Header)
	req.Header.Set("Content-Type", "application/json")
}

type person struct {
	XUID          string     `json:"xuid"`
	Gamertag      string     `json:"gamertag"`
	DisplayName   string     `json:"displayName"`
	PresenceState string     `json:"presenceState"`
	Added         *time.Time `json:"addedDateTimeUtc"`
	Following     bool       `json:"isFollowingCaller"`
	Followed      bool       `json:"isFollowedByCaller"`
}

func (p person) AddedTime() time.Time {
	if p.Added != nil {
		return *p.Added
	}
	return time.Time{}
}

func mergePerson(base, next person) person {
	if base.XUID == "" {
		return next
	}
	if next.Added != nil {
		base.Added = next.Added
	}
	if base.Gamertag == "" {
		base.Gamertag = next.Gamertag
	}
	if base.DisplayName == "" {
		base.DisplayName = next.DisplayName
	}
	if base.PresenceState == "" {
		base.PresenceState = next.PresenceState
	}
	base.Followed = base.Followed || next.Followed
	base.Following = base.Following || next.Following
	return base
}

var _ Provider = (*XboxProvider)(nil)
