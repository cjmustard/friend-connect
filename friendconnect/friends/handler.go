package friends

import (
	"context"
	"errors"
	"log"
	"sync"
	"time"

	"github.com/cjmustard/friend-connect/friendconnect/xbox"
)

type Friend struct {
	XUID      string    `json:"xuid"`
	Gamertag  string    `json:"gamertag"`
	Added     time.Time `json:"added"`
	Online    bool      `json:"online"`
	Following bool      `json:"following"`
	Followed  bool      `json:"followed"`
}

type Provider interface {
	ListFriends(ctx context.Context, acct *xbox.Account) ([]Friend, error)
	AddFriend(ctx context.Context, acct *xbox.Account, gamertag string) error
	AddFriendByXUID(ctx context.Context, acct *xbox.Account, xuid, gamertag string) error
	RemoveFriend(ctx context.Context, acct *xbox.Account, gamertag string) error
	PendingRequests(ctx context.Context, acct *xbox.Account) ([]Request, error)
	AcceptRequests(ctx context.Context, acct *xbox.Account, xuids []string) ([]Request, error)
}

type Options struct {
	AutoAccept bool
	AutoAdd    bool
	SyncEvery  time.Duration
}

type Request struct {
	XUID     string
	Gamertag string
}

type Handler struct {
	log      *log.Logger
	accounts *xbox.Store
	provider Provider
	friends  map[string][]Friend
	mu       sync.RWMutex
	opts     Options
}

func NewHandler(log *log.Logger, accounts *xbox.Store, provider Provider) *Handler {
	if provider == nil {
		provider = NewXboxProvider(nil)
	}
	return &Handler{log: log, accounts: accounts, provider: provider, friends: map[string][]Friend{}}
}

func (m *Handler) Configure(opts Options) {
	if opts.SyncEvery <= 0 {
		opts.SyncEvery = time.Minute
	}
	m.opts = opts
}

func (m *Handler) Run(ctx context.Context) {
	if m.opts.SyncEvery <= 0 {
		m.opts.SyncEvery = time.Minute
	}

	ticker := time.NewTicker(m.opts.SyncEvery)
	defer ticker.Stop()

	m.syncAndProcess(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.syncAndProcess(ctx)
		}
	}
}

func (m *Handler) syncAndProcess(ctx context.Context) {
	if err := m.Sync(ctx); err != nil {
		m.log.Printf("friend sync failed: %v (auto_add=%v auto_accept=%v)", err, m.opts.AutoAdd, m.opts.AutoAccept)
		return
	}

	m.logSyncSummary()

	if m.opts.AutoAdd {
		m.autoFollowBack(ctx)
	}

	if m.opts.AutoAccept {
		m.acceptPending(ctx)
	}
}

func (m *Handler) Sync(ctx context.Context) error {
	var wg sync.WaitGroup
	var firstErr error
	var once sync.Once

	m.accounts.WithAccounts(func(acct *xbox.Account) {
		wg.Add(1)
		go func(ac *xbox.Account) {
			defer wg.Done()
			tag := ac.Gamertag()

			friends, err := m.provider.ListFriends(ctx, ac)
			if err != nil {
				m.log.Printf("friend sync failed for %s: %v", tag, err)
				once.Do(func() { firstErr = err })
				return
			}

			m.mu.Lock()
			m.friends[tag] = friends
			m.mu.Unlock()

			m.log.Printf("account sync complete for %s: %d friends", tag, len(friends))
		}(acct)
	})

	wg.Wait()
	return firstErr
}

func (m *Handler) autoFollowBack(ctx context.Context) {
	m.accounts.WithAccounts(func(acct *xbox.Account) {
		tag := acct.Gamertag()
		friends := m.Friends(tag)
		followBackCount := 0

		for _, fr := range friends {
			if fr.XUID == "" {
				continue
			}
			if fr.Following && !fr.Followed {
				if err := m.provider.AddFriendByXUID(ctx, acct, fr.XUID, fr.Gamertag); err != nil {
					m.log.Printf("auto follow-back failed for %s -> %s (%s): %v", tag, fr.Gamertag, fr.XUID, err)
				} else {
					followBackCount++
				}
			}
		}

		if followBackCount > 0 {
			m.log.Printf("auto follow-back: %s (%d)", tag, followBackCount)
		}
	})
}

func (m *Handler) acceptPending(ctx context.Context) {
	m.accounts.WithAccounts(func(acct *xbox.Account) {
		tag := acct.Gamertag()
		requests, err := m.provider.PendingRequests(ctx, acct)
		if err != nil {
			m.log.Printf("fetch friend requests failed for %s: %v", tag, err)
			return
		}
		if len(requests) == 0 {
			return
		}

		xuids := make([]string, 0, len(requests))
		for _, r := range requests {
			xuids = append(xuids, r.XUID)
		}
		accepted, err := m.provider.AcceptRequests(ctx, acct, xuids)
		if err != nil {
			m.log.Printf("accept friend requests failed for %s (%d requests): %v", tag, len(requests), err)
			return
		}
		if len(accepted) == 0 {
			accepted = requests
		}

		for _, r := range accepted {
			name := r.Gamertag
			if name == "" {
				name = r.XUID
			}
		}

		if len(accepted) > 0 {
			m.log.Printf("friend requests accepted: %s (%d)", tag, len(accepted))
		}
	})
}

func (m *Handler) AutoAdd(ctx context.Context, gamertag string) error {
	if gamertag == "" {
		return errors.New("missing gamertag")
	}

	addedCount := 0
	m.accounts.WithAccounts(func(acct *xbox.Account) {
		tag := acct.Gamertag()
		if err := m.provider.AddFriend(ctx, acct, gamertag); err != nil {
			m.log.Printf("auto add friend failed for %s -> %s: %v", tag, gamertag, err)
		} else {
			addedCount++
		}
	})

	if addedCount > 0 {
		m.log.Printf("auto add: %s (%d)", gamertag, addedCount)
	}

	return nil
}

func (m *Handler) Friends(gamertag string) []Friend {
	m.mu.RLock()
	defer m.mu.RUnlock()
	friends := m.friends[gamertag]
	out := make([]Friend, len(friends))
	copySlice(out, friends)
	return out
}

func copySlice(dst, src []Friend) {
	copy(dst, src)
}

func (m *Handler) logSyncSummary() {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if len(m.friends) == 0 {
		return
	}

	totalFriends := 0
	onlineFriends := 0
	accountCount := len(m.friends)

	for _, friends := range m.friends {
		accountOnline := 0
		for _, friend := range friends {
			if friend.Online {
				accountOnline++
			}
		}
		totalFriends += len(friends)
		onlineFriends += accountOnline

	}

	if totalFriends > 0 {
		m.log.Printf("friend sync: %d accounts, %d total friends, %d online", accountCount, totalFriends, onlineFriends)
	}
}
