package session

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"time"

	"github.com/df-mc/go-nethernet"
	"github.com/google/uuid"
	"github.com/sandertv/gophertunnel/minecraft"

	"github.com/cjmustard/friend-connect/friendconnect/xbox"
)

func (m *Server) Listen(ctx context.Context, opts Options) error {
	if opts.Provider == nil {
		opts.Provider = minecraft.NewStatusProvider("Broadcaster", "Minecraft Presence Relay")
	}
	listener, err := minecraft.ListenConfig{
		StatusProvider: opts.Provider,
	}.Listen("raknet", opts.Addr)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}

	m.listener = listener
	m.captureListenerInfo(listener)
	if m.nether != nil {
		go m.listenNether(ctx, opts.Provider)
	}
	go func() {
		<-ctx.Done()
		listener.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			m.log.Printf("accept connection failed: %v", err)
			continue
		}

		minecraftConn := conn.(*minecraft.Conn)
		go func(mc *minecraft.Conn) {
			select {
			case <-ctx.Done():
				return
			case <-mc.Context().Done():
				m.log.Printf("main connection lost, attempting immediate reconnection")
				time.Sleep(connectionRetryDelay)
			}
		}(minecraftConn)
		go m.handleConn(ctx, minecraftConn)
	}
}

func (m *Server) captureListenerInfo(listener *minecraft.Listener) {
	if listener == nil {
		return
	}
	var port uint16
	if addr, ok := listener.Addr().(*net.UDPAddr); ok {
		port = uint16(addr.Port)
	}
	guid := m.listenGUID
	if guid == "" {
		guid = strings.ReplaceAll(uuid.NewString(), "-", "")
	}
	m.mu.Lock()
	m.listenPort = port
	m.listenGUID = guid
	m.mu.Unlock()

	go m.accounts.WithAccounts(func(acct *xbox.Account) {
		if err := m.ensureSession(context.Background(), acct); err != nil {
			m.log.Printf("update session failed for %s: %v", acct.Gamertag(), err)
		}
	})
}

func (m *Server) listenNether(ctx context.Context, provider minecraft.ServerStatusProvider) {
	if m.accounts == nil || m.nether == nil {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	m.setNetherRuntime(ctx, provider)
	m.accounts.WithAccounts(func(acct *xbox.Account) {
		m.startNetherForAccount(ctx, provider, acct)
	})
}

func (m *Server) listenNetherForAccount(ctx context.Context, provider minecraft.ServerStatusProvider, acct *xbox.Account) {
	networkName := m.nether.NetworkName(acct)
	if networkName == "" {
		networkName = fmt.Sprintf("nethernet:%s", acct.SessionID())
	}

	if ctx.Err() != nil {
		return
	}
	sig, done, err := m.nether.WaitSignaling(ctx, acct)
	if err != nil {
		if ctx.Err() != nil || errors.Is(err, context.Canceled) {
			return
		}
		m.log.Printf("wait nether signaling failed for %s: %v", acct.Gamertag(), err)
		return
	}
	if sig == nil {
		return
	}

	doneCh := done

	m.nether.RegisterNetwork(networkName, func(l *slog.Logger) minecraft.Network {
		if l == nil {
			l = slog.New(slog.NewTextHandler(os.Stdout, nil))
		}
		return minecraft.NetherNet{
			Signaling: sig,
			ListenConfig: nethernet.ListenConfig{
				Log: l,
			},
		}
	})

	listener, err := minecraft.ListenConfig{
		StatusProvider: provider,
	}.Listen(networkName, "")
	if err != nil {
		m.log.Printf("listen nether failed for %s: %v", acct.Gamertag(), err)
		return
	}

	acceptCtx, cancel := context.WithCancel(ctx)
	go func() {
		select {
		case <-doneCh:
		case <-ctx.Done():
		}
		cancel()
		_ = listener.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) || acceptCtx.Err() != nil {
				break
			}
			m.log.Printf("accept nether connection failed: %v", err)
			continue
		}

		netherConn := conn.(*minecraft.Conn)
		go m.handleConn(acceptCtx, netherConn)
	}

	cancel()
	_ = listener.Close()
}
