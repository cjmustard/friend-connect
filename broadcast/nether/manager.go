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

	pending chan *Session
}

type Session struct {
	manager *Manager
	account *account.Account

	networkID uint64

	ready     chan struct{}
	readyOnce sync.Once

	mu               sync.Mutex
	pendingTransfers int
}

type notifier struct {
	done chan struct{}
	once sync.Once
	log  *logger.Logger
	tag  string
	sess *Session
}

func (n *notifier) NotifySignal(signal *nethernet.Signal) {
	if n.log == nil || signal == nil {
		return
	}

	switch signal.Type {
	case nethernet.SignalTypeOffer:
		n.log.Infof("nethernet connection request for %s (connection %d, network %d)", n.tag, signal.ConnectionID, signal.NetworkID)
		if n.sess != nil {
			n.sess.flagTransfer()
		}
	case nethernet.SignalTypeAnswer:
		n.log.Infof("nethernet connection established for %s (connection %d)", n.tag, signal.ConnectionID)
	case nethernet.SignalTypeError:
		if signal.Data != "" {
			n.log.Warnf("nethernet connection error for %s (connection %d): %s", n.tag, signal.ConnectionID, signal.Data)
		} else {
			n.log.Warnf("nethernet connection error for %s (connection %d)", n.tag, signal.ConnectionID)
		}
	default:
		n.log.Debugf("nethernet signal for %s: type=%s connection=%d", n.tag, signal.Type, signal.ConnectionID)
	}
}

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
		pending:  make(chan *Session, 32),
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
		sess.manager = m
		return sess
	}
	sess := &Session{
		manager:   m,
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
		stop := conn.Notify(&notifier{done: done, log: m.log, tag: acct.Gamertag(), sess: sess})

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

// TokenSource returns an oauth2.TokenSource for the provided account using the
// account's refresh token. If the account is nil or does not have a refresh
// token available, nil is returned.
func (m *Manager) TokenSource(acct *account.Account) oauth2.TokenSource {
	if acct == nil {
		return nil
	}
	refresh := acct.RefreshToken()
	if refresh == "" {
		return nil
	}
	return m.tokenSource(refresh)
}

func randomUint64() uint64 {
	var b [8]byte
	if _, err := crand.Read(b[:]); err == nil {
		return binary.BigEndian.Uint64(b[:])
	}
	return rand.Uint64()
}

func (s *Session) flagTransfer() {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.pendingTransfers++
	s.mu.Unlock()
	if s.manager != nil {
		s.manager.enqueuePending(s)
	}
}

func (s *Session) consumeTransfer() bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pendingTransfers == 0 {
		return false
	}
	s.pendingTransfers--
	return true
}

func (m *Manager) enqueuePending(sess *Session) {
	if m == nil || sess == nil || m.pending == nil {
		return
	}
	select {
	case m.pending <- sess:
	default:
		if m.log != nil {
			acct := ""
			if sess.account != nil {
				acct = sess.account.Gamertag()
			}
			if acct != "" {
				m.log.Debugf("pending transfer queue full for %s", acct)
			} else {
				m.log.Debug("pending transfer queue full")
			}
		}
	}
}

func (m *Manager) sessionsSnapshot() []*Session {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.sessions) == 0 {
		return nil
	}
	sessions := make([]*Session, 0, len(m.sessions))
	for _, sess := range m.sessions {
		sessions = append(sessions, sess)
	}
	return sessions
}

func (m *Manager) ClaimPending(ctx context.Context) *account.Account {
	if m == nil {
		return nil
	}
	sessions := m.sessionsSnapshot()
	for _, sess := range sessions {
		if sess.consumeTransfer() {
			return sess.account
		}
	}
	if ctx == nil {
		ctx = context.Background()
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case sess := <-m.pending:
			if sess == nil {
				continue
			}
			if sess.consumeTransfer() {
				return sess.account
			}
		}
	}
}
