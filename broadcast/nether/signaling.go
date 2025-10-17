package nether

import (
	"context"
	crand "crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"math/rand"
	"sync"
	"time"

	"github.com/df-mc/go-nethernet"
	"github.com/sandertv/gophertunnel/minecraft"
	"github.com/sandertv/gophertunnel/minecraft/auth"
	"github.com/sandertv/gophertunnel/minecraft/auth/authclient"
	"github.com/sandertv/gophertunnel/minecraft/auth/franchise/signaling"
	"golang.org/x/oauth2"

	"github.com/cjmustard/consoleconnect/broadcast/account"
	"github.com/cjmustard/consoleconnect/broadcast/logger"
)

type SignalingHub struct {
	log      *logger.Logger
	accounts *account.Manager

	mu       sync.Mutex
	sessions map[string]*SignalingSession

	pending chan *SignalingSession

	networkMu sync.Mutex

	ctx   context.Context
	ctxMu sync.RWMutex
}

type SignalingSession struct {
	manager *SignalingHub
	account *account.Account

	networkID   uint64
	networkName string

	ready     chan struct{}
	readyOnce sync.Once

	startOnce sync.Once

	mu               sync.Mutex
	pendingTransfers int

	sigMu           sync.RWMutex
	signaling       nethernet.Signaling
	signalingDone   <-chan struct{}
	signalingNotify chan struct{}
}

type notifier struct {
	done chan struct{}
	once sync.Once
	log  *logger.Logger
	tag  string
	sess *SignalingSession
}

func (n *notifier) NotifySignal(signal *nethernet.Signal) {
	if n.log == nil || signal == nil {
		return
	}

	switch signal.Type {
	case nethernet.SignalTypeOffer:
		n.log.Debugf("nethernet connection request for %s (connection %d, network %d)", n.tag, signal.ConnectionID, signal.NetworkID)
		if n.sess != nil {
			n.sess.flagTransfer()
		}
	case nethernet.SignalTypeAnswer:
		n.log.Debugf("nethernet connection established for %s (connection %d)", n.tag, signal.ConnectionID)
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

func NewHub(log *logger.Logger, accounts *account.Manager) *SignalingHub {
	if log == nil {
		log = logger.New()
	}
	return &SignalingHub{
		log:      log,
		accounts: accounts,
		sessions: map[string]*SignalingSession{},
		pending:  make(chan *SignalingSession, 32),
	}
}

func (h *SignalingHub) Start(ctx context.Context) {
	if h.accounts == nil {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	h.setContext(ctx)
	h.accounts.WithAccounts(func(acct *account.Account) {
		h.startSession(acct)
	})
}

func (h *SignalingHub) AttachAccount(acct *account.Account) {
	if acct == nil {
		return
	}
	h.startSession(acct)
}

func (h *SignalingHub) setContext(ctx context.Context) {
	h.ctxMu.Lock()
	h.ctx = ctx
	h.ctxMu.Unlock()
}

func (h *SignalingHub) sessionContext() context.Context {
	h.ctxMu.RLock()
	ctx := h.ctx
	h.ctxMu.RUnlock()
	if ctx == nil {
		return context.Background()
	}
	return ctx
}

func (h *SignalingHub) startSession(acct *account.Account) {
	if acct == nil {
		return
	}
	sess := h.sessionFor(acct)
	if sess == nil {
		return
	}
	sess.startOnce.Do(func() {
		go h.runSession(h.sessionContext(), acct, sess)
	})
}

func (m *SignalingHub) NetworkID(ctx context.Context, acct *account.Account) (uint64, error) {
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

func (m *SignalingHub) NetworkName(acct *account.Account) string {
	if acct == nil {
		return ""
	}
	sess := m.sessionFor(acct)
	if sess == nil {
		return ""
	}
	return sess.network()
}

func (m *SignalingHub) WaitSignaling(ctx context.Context, acct *account.Account) (nethernet.Signaling, <-chan struct{}, error) {
	if acct == nil {
		return nil, nil, errors.New("nil account")
	}
	sess := m.sessionFor(acct)
	if sess == nil {
		return nil, nil, errors.New("session unavailable")
	}

	select {
	case <-sess.ready:
	default:
		select {
		case <-sess.ready:
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		}
	}

	for {
		sig, done := sess.signalingState()
		if sig != nil {
			return sig, done, nil
		}
		select {
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		case <-sess.signalingNotify:
		}
	}
}

func (m *SignalingHub) RegisterNetwork(name string, factory func(*slog.Logger) minecraft.Network) {
	if name == "" || factory == nil {
		return
	}
	m.networkMu.Lock()
	minecraft.RegisterNetwork(name, factory)
	m.networkMu.Unlock()
}

func (m *SignalingHub) sessionFor(acct *account.Account) *SignalingSession {
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
	sess := &SignalingSession{
		manager:         m,
		account:         acct,
		networkID:       randomUint64(),
		networkName:     fmt.Sprintf("nethernet:%s", acct.SessionID()),
		ready:           make(chan struct{}),
		signalingNotify: make(chan struct{}, 1),
	}
	m.sessions[id] = sess
	return sess
}

func (m *SignalingHub) runSession(ctx context.Context, acct *account.Account, sess *SignalingSession) {
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
		done := make(chan struct{})
		sess.setSignaling(conn, done)
		sess.readyOnce.Do(func() { close(sess.ready) })
		m.log.Debugf("nethernet signaling ready for %s (network %d)", acct.Gamertag(), sess.networkID)

		stop := conn.Notify(&notifier{done: done, log: m.log, tag: acct.Gamertag(), sess: sess})

		select {
		case <-ctx.Done():
			stop()
			_ = conn.Close()
			sess.setSignaling(nil, nil)
			return
		case <-done:
			stop()
			_ = conn.Close()
			sess.setSignaling(nil, nil)
			if ctx.Err() != nil {
				return
			}
			m.log.Warnf("nethernet signaling disconnected for %s, retrying", acct.Gamertag())
			continue
		}
	}
}

func (m *SignalingHub) tokenSource(refresh string) oauth2.TokenSource {
	seed := &oauth2.Token{RefreshToken: refresh, Expiry: time.Now().Add(-time.Hour)}
	base := auth.RefreshTokenSource(seed)
	return oauth2.ReuseTokenSource(seed, base)
}

// TokenSource returns an oauth2.TokenSource for the provided account using the
// account's refresh token. If the account is nil or does not have a refresh
// token available, nil is returned.
func (m *SignalingHub) TokenSource(acct *account.Account) oauth2.TokenSource {
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

func (s *SignalingSession) setSignaling(sig nethernet.Signaling, done <-chan struct{}) {
	if s == nil {
		return
	}
	s.sigMu.Lock()
	s.signaling = sig
	s.signalingDone = done
	s.sigMu.Unlock()
	if s.signalingNotify != nil {
		select {
		case s.signalingNotify <- struct{}{}:
		default:
		}
	}
}

func (s *SignalingSession) signalingState() (nethernet.Signaling, <-chan struct{}) {
	s.sigMu.RLock()
	defer s.sigMu.RUnlock()
	return s.signaling, s.signalingDone
}

func (s *SignalingSession) network() string {
	if s == nil {
		return ""
	}
	return s.networkName
}

func (s *SignalingSession) flagTransfer() {
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

func (s *SignalingSession) consumeTransfer() bool {
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

func (m *SignalingHub) enqueuePending(sess *SignalingSession) {
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

func (m *SignalingHub) sessionsSnapshot() []*SignalingSession {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.sessions) == 0 {
		return nil
	}
	sessions := make([]*SignalingSession, 0, len(m.sessions))
	for _, sess := range m.sessions {
		sessions = append(sessions, sess)
	}
	return sessions
}

func (m *SignalingHub) ClaimPending(ctx context.Context) *account.Account {
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
