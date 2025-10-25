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
	m.mu.Lock()
	m.conns[addr] = conn
	m.mu.Unlock()
	defer m.CloseClient(addr)

	if err := conn.StartGame(minecraft.GameData{}); err != nil {
		m.log.Printf("start game failed: %v", err)
		return
	}

	if m.relay.RemoteAddress != "" {
		m.handleRelayTransfer(ctx, conn)
		return
	}

	m.monitorConnection(ctx, addr, conn)
}

func (m *Server) handleRelayTransfer(ctx context.Context, conn *minecraft.Conn) {
	clientData := conn.ClientData()
	identity := conn.IdentityData()
	clientName := clientData.ThirdPartyName
	if clientName == "" {
		clientName = identity.DisplayName
	}
	m.log.Printf("transferring client %s to %s", clientName, m.relay.RemoteAddress)

	host, portStr, err := net.SplitHostPort(m.relay.RemoteAddress)
	if err != nil {
		m.log.Printf("relay transfer failed: %v", err)
		m.notifyTransferFailure(conn, err)
		return
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		m.log.Printf("relay transfer failed: %v", err)
		m.notifyTransferFailure(conn, err)
		return
	}
	if err := conn.WritePacket(&packet.Transfer{Address: host, Port: uint16(port)}); err != nil {
		m.log.Printf("relay transfer failed: %v", err)
		m.notifyTransferFailure(conn, err)
		return
	}
	if err := conn.Flush(); err != nil {
		m.log.Printf("relay transfer failed: %v", err)
		m.notifyTransferFailure(conn, err)
		return
	}

	wait := m.relay.Timeout
	if wait <= 0 {
		wait = transferWaitTimeout
	}
	select {
	case <-ctx.Done():
	case <-time.After(wait):
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

func (m *Server) notifyTransferFailure(conn *minecraft.Conn, relayErr error) {
	_ = conn.WritePacket(&packet.Disconnect{
		Reason:  packet.DisconnectReasonKicked,
		Message: fmt.Sprintf("Unable to reach the relay destination: %v", relayErr),
	})
	_ = conn.Flush()
}
