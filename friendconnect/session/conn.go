package session

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/sandertv/gophertunnel/minecraft"
	"github.com/sandertv/gophertunnel/minecraft/protocol/packet"
)

func (m *Server) handleConn(ctx context.Context, conn *minecraft.Conn) {
	addr := conn.RemoteAddr().String()
	m.registerConnection(addr, conn)
	defer m.CloseClient(addr)

	// Start the game first for all connections
	if err := conn.StartGame(minecraft.GameData{}); err != nil {
		m.log.Printf("start game failed: %v", err)
		return
	}

	// If relay is configured, wait for game to load then transfer
	if m.relay.RemoteAddress != "" {
		m.handleRelayTransfer(ctx, conn)
		return
	}

	m.monitorConnection(ctx, addr, conn)
}

func (m *Server) registerConnection(addr string, conn *minecraft.Conn) {
	m.mu.Lock()
	m.conns[addr] = conn
	m.mu.Unlock()
}

func (m *Server) handleRelayTransfer(ctx context.Context, conn *minecraft.Conn) {
	clientData := conn.ClientData()
	identity := conn.IdentityData()
	clientName := clientData.ThirdPartyName
	if clientName == "" {
		clientName = identity.DisplayName
	}

	m.log.Printf("transferring client %s to %s", clientName, m.relay.RemoteAddress)

	if err := m.transferClient(ctx, conn); err != nil {
		m.log.Printf("relay transfer failed: %v", err)
		m.notifyTransferFailure(conn, err)
	}
}

func (m *Server) monitorConnection(ctx context.Context, addr string, conn *minecraft.Conn) {
	select {
	case <-ctx.Done():
		return
	case <-conn.Context().Done():
		m.log.Printf("connection lost for %s", addr)
	}
}

func (m *Server) CloseClient(addr string) {
	m.mu.Lock()
	if conn, ok := m.conns[addr]; ok {
		conn.Close()
		delete(m.conns, addr)
	}
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
