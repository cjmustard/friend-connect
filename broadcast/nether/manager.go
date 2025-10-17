package nether

import (
	"context"
	crand "crypto/rand"
	"encoding/binary"
	"errors"
	"math/rand"
	"sync"
	"time"

	"github.com/df-mc/go-nethernet"
	"github.com/sandertv/gophertunnel/minecraft/auth"
	"github.com/sandertv/gophertunnel/minecraft/auth/authclient"
	"github.com/sandertv/gophertunnel/minecraft/auth/franchise/signaling"
	"golang.org/x/oauth2"

	"github.com/cjmustard/consoleconnect/broadcast/account"
	"github.com/cjmustard/consoleconnect/broadcast/logger"
)

type Manager struct {
	log      *logger.Logger
	accounts *account.Manager

	mu       sync.Mutex
	sessions map[string]*Session
}

type Session struct {
	account *account.Account

	networkID uint64

	ready     chan struct{}
	readyOnce sync.Once
}

type notifier struct {
	done chan struct{}
	once sync.Once
	log  *logger.Logger
	tag  string
}

func (n *notifier) NotifySignal(*nethernet.Signal) {}

func (n *notifier) NotifyError(err error) {
	if err != nil && !errors.Is(err, nethernet.ErrSignalingStopped) && n.log != nil {
		n.log.Errorf("nethernet signaling error for %s: %v", n.tag, err)
	}
	n.once.Do(func() { close(n.done) })
}

func NewManager(log *logger.Logger, accounts *account.Manager) *Manager {
	if log == nil {
		log = logger.New()
	}
	return &Manager{
		log:      log,
		accounts: accounts,
		sessions: map[string]*Session{},
	}
}

func (m *Manager) Start(ctx context.Context) {
	if m.accounts == nil {
		return
	}
	m.accounts.WithAccounts(func(acct *account.Account) {
		sess := m.sessionFor(acct)
		go m.runSession(ctx, acct, sess)
	})
}

func (m *Manager) NetworkID(ctx context.Context, acct *account.Account) (uint64, error) {
	if acct == nil {
		return 0, errors.New("nil account")
	}
	sess := m.sessionFor(acct)
	select {
	case <-sess.ready:
		return sess.networkID, nil
	case <-ctx.Done():
		return 0, ctx.Err()
	}
}

func (m *Manager) sessionFor(acct *account.Account) *Session {
	if acct == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	id := acct.SessionID()
	if sess, ok := m.sessions[id]; ok {
		return sess
	}
	sess := &Session{
		account:   acct,
		networkID: randomUint64(),
		ready:     make(chan struct{}),
	}
	m.sessions[id] = sess
	return sess
}

func (m *Manager) runSession(ctx context.Context, acct *account.Account, sess *Session) {
	if acct == nil || sess == nil {
		return
	}

	backoff := 5 * time.Second
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		src := m.tokenSource(acct.RefreshToken())
		d := signaling.Dialer{
			NetworkID:  sess.networkID,
			AuthClient: authclient.DefaultClient,
		}
		connectCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
		conn, err := d.DialContext(connectCtx, src)
		cancel()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			m.log.Errorf("dial nethernet for %s: %v", acct.Gamertag(), err)
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return
			}
			if backoff < time.Minute {
				backoff *= 2
			}
			continue
		}

		backoff = 5 * time.Second
		sess.readyOnce.Do(func() { close(sess.ready) })
		m.log.Infof("nethernet signaling ready for %s (network %d)", acct.Gamertag(), sess.networkID)

		done := make(chan struct{})
		stop := conn.Notify(&notifier{done: done, log: m.log, tag: acct.Gamertag()})

		select {
		case <-ctx.Done():
			stop()
			_ = conn.Close()
			return
		case <-done:
			stop()
			_ = conn.Close()
			if ctx.Err() != nil {
				return
			}
			m.log.Warnf("nethernet signaling disconnected for %s, retrying", acct.Gamertag())
			continue
		}
	}
}

func (m *Manager) tokenSource(refresh string) oauth2.TokenSource {
	seed := &oauth2.Token{RefreshToken: refresh, Expiry: time.Now().Add(-time.Hour)}
	base := auth.RefreshTokenSource(seed)
	return oauth2.ReuseTokenSource(seed, base)
}

func randomUint64() uint64 {
	var b [8]byte
	if _, err := crand.Read(b[:]); err == nil {
		return binary.BigEndian.Uint64(b[:])
	}
	return rand.Uint64()
}
