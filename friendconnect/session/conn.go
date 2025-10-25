package session

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/sandertv/gophertunnel/minecraft"
	"github.com/sandertv/gophertunnel/minecraft/protocol/packet"

	"github.com/cjmustard/friend-connect/friendconnect/xbox"
)

func (m *Server) handleConn(ctx context.Context, conn *minecraft.Conn) {
	addr := conn.RemoteAddr().String()
	m.registerConnection(addr, conn)
	defer m.CloseClient(addr)

	host, err := m.waitForHostIfRequired(ctx, addr, conn)
	if err != nil {
		return
	}

	m.trackClient(addr, host, conn)
	if err := m.startClientGame(conn); err != nil {
		return
	}

	if m.relay.RemoteAddress != "" {
		m.handleRelayTransfer(ctx, conn, host)
		return
	}

	m.monitorConnection(ctx, addr, conn, host)
}

func (m *Server) registerConnection(addr string, conn *minecraft.Conn) {
	m.mu.Lock()
	m.conns[addr] = conn
	m.mu.Unlock()
}

func (m *Server) waitForHostIfRequired(ctx context.Context, addr string, conn *minecraft.Conn) (*xbox.Account, error) {
	if m.relay.RemoteAddress == "" || m.nether == nil {
		return nil, nil
	}

	host, err := m.waitForTransferFlag(ctx)
	if host != nil {
		return host, nil
	}

	if ctx.Err() != nil || errors.Is(err, context.Canceled) {
		return nil, err
	}
	if errors.Is(err, context.DeadlineExceeded) {
		m.log.Printf("timed out waiting for transfer flag: %s", addr)
	} else {
		m.log.Printf("no pending transfer available: %s", addr)
	}
	m.notifyNoPendingTransfer(conn)
	return nil, err
}

func (m *Server) startClientGame(conn *minecraft.Conn) error {
	if err := conn.StartGame(minecraft.GameData{}); err != nil {
		m.log.Printf("start game failed: %v", err)
		return err
	}
	return nil
}

func (m *Server) handleRelayTransfer(ctx context.Context, conn *minecraft.Conn, host *xbox.Account) {
	clientData := conn.ClientData()
	identity := conn.IdentityData()
	clientName := clientData.ThirdPartyName
	if clientName == "" {
		clientName = identity.DisplayName
	}

	if host != nil {
		m.log.Printf("transferring client %s to %s (host: %s)", clientName, m.relay.RemoteAddress, host.Gamertag())
	} else {
		m.log.Printf("transferring client %s to %s", clientName, m.relay.RemoteAddress)
	}

	if err := m.transferClient(ctx, conn); err != nil {
		m.log.Printf("relay transfer failed: %v", err)
		m.notifyTransferFailure(conn, err)
	}
}

func (m *Server) monitorConnection(ctx context.Context, addr string, conn *minecraft.Conn, host *xbox.Account) {
	select {
	case <-ctx.Done():
		return
	case <-conn.Context().Done():
		m.log.Printf("connection lost for %s, initiating reconnection", addr)
		if host != nil {
			go m.reconnectClient(addr, host)
		}
	}
}

func (m *Server) reconnectClient(addr string, host *xbox.Account) {
	if m.nether == nil || host == nil {
		return
	}

	ctx := m.sessionContext()
	reconnectCtx, cancel := context.WithTimeout(ctx, reconnectTimeout)
	defer cancel()

	for {
		if reconnectCtx.Err() != nil {
			m.log.Printf("reconnection timeout for %s", addr)
			return
		}

		if err := m.ensureSession(reconnectCtx, host); err != nil {
			m.log.Printf("reconnection session failed for %s: %v", addr, err)
			time.Sleep(reconnectRetryInterval)
			continue
		}

		m.log.Printf("reconnection successful for %s", addr)
		return
	}
}

func (m *Server) waitForTransferFlag(ctx context.Context) (*xbox.Account, error) {
	if m.nether == nil {
		return nil, nil
	}
	timeout := m.relay.Timeout
	if timeout <= 0 {
		timeout = transferFlagTimeout
	}
	waitCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	acct := m.nether.ClaimPending(waitCtx)
	if acct != nil {
		return acct, nil
	}
	return nil, waitCtx.Err()
}

func (m *Server) notifyNoPendingTransfer(conn *minecraft.Conn) {
	if conn == nil {
		return
	}
	_ = conn.WritePacket(&packet.Disconnect{
		Reason:  packet.DisconnectReasonKicked,
		Message: "Unable to join: Host not ready. Please try again shortly.",
	})
	_ = conn.Flush()
}

func (m *Server) handlePackets(header packet.Header, payload []byte, src net.Addr, dst net.Addr) {
	subs := m.lookupClient(src.String())
	if subs == nil {
		return
	}
	subs.UpdateLastPing()
}

func (m *Server) lookupClient(addr string) *ClientSession {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.subsessions[addr]
}

func (m *Server) trackClient(addr string, acct *xbox.Account, conn *minecraft.Conn) *ClientSession {
	subs := &ClientSession{Account: acct, Conn: conn, LastPing: time.Now()}
	m.mu.Lock()
	m.subsessions[addr] = subs
	m.mu.Unlock()
	return subs
}

func (m *Server) CloseClient(addr string) {
	m.mu.Lock()
	if conn, ok := m.conns[addr]; ok {
		conn.Close()
		delete(m.conns, addr)
	}
	delete(m.subsessions, addr)
	m.mu.Unlock()
}

func (m *Server) transferClient(ctx context.Context, conn *minecraft.Conn) error {
	host, portStr, err := net.SplitHostPort(m.relay.RemoteAddress)
	if err != nil {
		return fmt.Errorf("invalid relay address: %w", err)
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return fmt.Errorf("parse relay port: %w", err)
	}

	if err := conn.WritePacket(&packet.Transfer{Address: host, Port: uint16(port)}); err != nil {
		return fmt.Errorf("send transfer packet: %w", err)
	}
	if err := conn.Flush(); err != nil {
		return fmt.Errorf("flush transfer packet: %w", err)
	}

	wait := m.relay.Timeout
	if wait <= 0 {
		wait = transferWaitTimeout
	}
	select {
	case <-ctx.Done():
	case <-time.After(wait):
	}
	return nil
}

func (m *Server) notifyTransferFailure(conn *minecraft.Conn, relayErr error) {
	msg := fmt.Sprintf("Unable to reach the relay destination: %v", relayErr)
	_ = conn.WritePacket(&packet.Disconnect{
		Reason:  packet.DisconnectReasonKicked,
		Message: msg,
	})
	_ = conn.Flush()
}

func (s *ClientSession) UpdateLastPing() {
	s.mu.Lock()
	s.LastPing = time.Now()
	s.mu.Unlock()
}
