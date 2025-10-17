package friends

import (
	"context"
	"fmt"
	"time"

	"github.com/cjmustard/console-connect/internal/broadcaster/account"
	"github.com/cjmustard/console-connect/internal/broadcaster/storage"
)

type StoredProvider struct {
	backend storage.Backend
}

func NewStoredProvider(backend storage.Backend) *StoredProvider {
	return &StoredProvider{backend: backend}
}

func (p *StoredProvider) ListFriends(ctx context.Context, acct *account.Account) ([]Friend, error) {
	var friends []Friend
	if err := p.backend.Load(p.key(acct.Gamertag), &friends); err != nil {
		return nil, err
	}
	return friends, nil
}

func (p *StoredProvider) AddFriend(ctx context.Context, acct *account.Account, gamertag string) error {
	var friends []Friend
	if err := p.backend.Load(p.key(acct.Gamertag), &friends); err != nil {
		return err
	}
	friends = append(friends, Friend{Gamertag: gamertag, Added: time.Now(), Online: true})
	return p.backend.Save(p.key(acct.Gamertag), friends)
}

func (p *StoredProvider) RemoveFriend(ctx context.Context, acct *account.Account, gamertag string) error {
	var friends []Friend
	if err := p.backend.Load(p.key(acct.Gamertag), &friends); err != nil {
		return err
	}
	result := friends[:0]
	for _, f := range friends {
		if f.Gamertag != gamertag {
			result = append(result, f)
		}
	}
	return p.backend.Save(p.key(acct.Gamertag), result)
}

func (p *StoredProvider) key(gamertag string) string {
	return fmt.Sprintf("friends_%s", gamertag)
}
