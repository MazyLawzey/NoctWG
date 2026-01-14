/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2025 NoctWG. All Rights Reserved.
 */

package rpft

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// RPFT - Reverse Port Forwarding Tunnel
// Allows forwarding ports from the VPN client to the server or vice versa

// TunnelType defines the direction of the tunnel
type TunnelType uint8

const (
	// TunnelTypeLocalToRemote forwards a local port to a remote port
	TunnelTypeLocalToRemote TunnelType = 1
	// TunnelTypeRemoteToLocal forwards a remote port to a local port
	TunnelTypeRemoteToLocal TunnelType = 2
)

// TunnelProtocol defines the protocol for the tunnel
type TunnelProtocol uint8

const (
	TunnelProtocolTCP TunnelProtocol = 1
	TunnelProtocolUDP TunnelProtocol = 2
)

// TunnelState represents the state of a tunnel
type TunnelState uint8

const (
	TunnelStateInactive TunnelState = iota
	TunnelStateActive
	TunnelStatePending
	TunnelStateError
)

// Tunnel represents an RPFT tunnel configuration
type Tunnel struct {
	ID           uint32
	Name         string
	Type         TunnelType
	Protocol     TunnelProtocol
	LocalPort    uint16
	RemotePort   uint16
	LocalHost    string
	RemoteHost   string
	State        TunnelState
	BytesSent    uint64
	BytesRecv    uint64
	Connections  int32
	CreatedAt    time.Time
	LastActivity time.Time

	// Internal
	listener net.Listener
	mutex    sync.RWMutex
	closed   chan struct{}
}

// Connection represents an active tunnel connection
type Connection struct {
	ID         uint32
	TunnelID   uint32
	LocalConn  net.Conn
	RemoteConn net.Conn
	CreatedAt  time.Time
	BytesSent  uint64
	BytesRecv  uint64
	closed     chan struct{}
}

// Manager manages all RPFT tunnels
type Manager struct {
	tunnels      map[uint32]*Tunnel
	connections  map[uint32]*Connection
	tunnelsMutex sync.RWMutex
	connMutex    sync.RWMutex
	nextID       uint32
	nextConnID   uint32

	// Callbacks
	onTunnelData  func(tunnelID uint32, connID uint32, data []byte) error
	onTunnelOpen  func(tunnelID uint32, connID uint32) error
	onTunnelClose func(tunnelID uint32, connID uint32) error

	closed chan struct{}
}

// NewManager creates a new RPFT manager
func NewManager() *Manager {
	return &Manager{
		tunnels:     make(map[uint32]*Tunnel),
		connections: make(map[uint32]*Connection),
		closed:      make(chan struct{}),
	}
}

// CreateTunnel creates a new tunnel
func (m *Manager) CreateTunnel(config TunnelConfig) (*Tunnel, error) {
	m.tunnelsMutex.Lock()
	defer m.tunnelsMutex.Unlock()

	id := atomic.AddUint32(&m.nextID, 1)

	tunnel := &Tunnel{
		ID:         id,
		Name:       config.Name,
		Type:       config.Type,
		Protocol:   config.Protocol,
		LocalPort:  config.LocalPort,
		RemotePort: config.RemotePort,
		LocalHost:  config.LocalHost,
		RemoteHost: config.RemoteHost,
		State:      TunnelStateInactive,
		CreatedAt:  time.Now(),
		closed:     make(chan struct{}),
	}

	if tunnel.LocalHost == "" {
		tunnel.LocalHost = "127.0.0.1"
	}
	if tunnel.RemoteHost == "" {
		tunnel.RemoteHost = "127.0.0.1"
	}

	m.tunnels[id] = tunnel
	return tunnel, nil
}

// TunnelConfig defines tunnel configuration
type TunnelConfig struct {
	Name       string
	Type       TunnelType
	Protocol   TunnelProtocol
	LocalPort  uint16
	RemotePort uint16
	LocalHost  string
	RemoteHost string
}

// StartTunnel starts a tunnel
func (m *Manager) StartTunnel(id uint32) error {
	m.tunnelsMutex.RLock()
	tunnel, exists := m.tunnels[id]
	m.tunnelsMutex.RUnlock()

	if !exists {
		return errors.New("tunnel not found")
	}

	tunnel.mutex.Lock()
	defer tunnel.mutex.Unlock()

	if tunnel.State == TunnelStateActive {
		return errors.New("tunnel already active")
	}

	switch tunnel.Protocol {
	case TunnelProtocolTCP:
		return m.startTCPTunnel(tunnel)
	case TunnelProtocolUDP:
		return m.startUDPTunnel(tunnel)
	default:
		return errors.New("unsupported protocol")
	}
}

// startTCPTunnel starts a TCP tunnel
func (m *Manager) startTCPTunnel(tunnel *Tunnel) error {
	if tunnel.Type == TunnelTypeLocalToRemote {
		// Listen on local port
		addr := net.JoinHostPort(tunnel.LocalHost, itoa(int(tunnel.LocalPort)))
		listener, err := net.Listen("tcp", addr)
		if err != nil {
			tunnel.State = TunnelStateError
			return err
		}

		tunnel.listener = listener
		tunnel.State = TunnelStateActive

		go m.acceptTCPConnections(tunnel)
	} else {
		// Remote to local - notify remote side to start listening
		tunnel.State = TunnelStatePending
		// This will be handled by the remote peer
	}

	return nil
}

// startUDPTunnel starts a UDP tunnel
func (m *Manager) startUDPTunnel(tunnel *Tunnel) error {
	if tunnel.Type == TunnelTypeLocalToRemote {
		addr := net.JoinHostPort(tunnel.LocalHost, itoa(int(tunnel.LocalPort)))
		udpAddr, err := net.ResolveUDPAddr("udp", addr)
		if err != nil {
			return err
		}

		conn, err := net.ListenUDP("udp", udpAddr)
		if err != nil {
			tunnel.State = TunnelStateError
			return err
		}

		tunnel.State = TunnelStateActive
		go m.handleUDPTunnel(tunnel, conn)
	}

	return nil
}

// acceptTCPConnections accepts incoming TCP connections
func (m *Manager) acceptTCPConnections(tunnel *Tunnel) {
	for {
		select {
		case <-tunnel.closed:
			return
		case <-m.closed:
			return
		default:
		}

		conn, err := tunnel.listener.Accept()
		if err != nil {
			continue
		}

		go m.handleTCPConnection(tunnel, conn)
	}
}

// handleTCPConnection handles a TCP connection
func (m *Manager) handleTCPConnection(tunnel *Tunnel, localConn net.Conn) {
	connID := atomic.AddUint32(&m.nextConnID, 1)

	connection := &Connection{
		ID:        connID,
		TunnelID:  tunnel.ID,
		LocalConn: localConn,
		CreatedAt: time.Now(),
		closed:    make(chan struct{}),
	}

	m.connMutex.Lock()
	m.connections[connID] = connection
	m.connMutex.Unlock()

	atomic.AddInt32(&tunnel.Connections, 1)

	// Notify about new connection
	if m.onTunnelOpen != nil {
		if err := m.onTunnelOpen(tunnel.ID, connID); err != nil {
			localConn.Close()
			return
		}
	}

	// Start reading from local connection
	go m.readFromLocal(tunnel, connection)
}

// readFromLocal reads data from local connection and forwards it
func (m *Manager) readFromLocal(tunnel *Tunnel, conn *Connection) {
	defer func() {
		conn.LocalConn.Close()
		if m.onTunnelClose != nil {
			m.onTunnelClose(tunnel.ID, conn.ID)
		}
		m.connMutex.Lock()
		delete(m.connections, conn.ID)
		m.connMutex.Unlock()
		atomic.AddInt32(&tunnel.Connections, -1)
	}()

	buf := make([]byte, 32768)
	for {
		select {
		case <-conn.closed:
			return
		case <-tunnel.closed:
			return
		default:
		}

		n, err := conn.LocalConn.Read(buf)
		if err != nil {
			return
		}

		if m.onTunnelData != nil {
			if err := m.onTunnelData(tunnel.ID, conn.ID, buf[:n]); err != nil {
				return
			}
		}

		atomic.AddUint64(&conn.BytesSent, uint64(n))
		atomic.AddUint64(&tunnel.BytesSent, uint64(n))
		tunnel.LastActivity = time.Now()
	}
}

// handleUDPTunnel handles UDP tunnel
func (m *Manager) handleUDPTunnel(tunnel *Tunnel, conn *net.UDPConn) {
	defer conn.Close()

	buf := make([]byte, 65535)
	for {
		select {
		case <-tunnel.closed:
			return
		case <-m.closed:
			return
		default:
		}

		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			continue
		}

		// Create virtual connection ID from address
		connID := addrToConnID(addr)

		if m.onTunnelData != nil {
			m.onTunnelData(tunnel.ID, connID, buf[:n])
		}

		atomic.AddUint64(&tunnel.BytesSent, uint64(n))
		tunnel.LastActivity = time.Now()
	}
}

// WriteToConnection writes data to a connection
func (m *Manager) WriteToConnection(connID uint32, data []byte) error {
	m.connMutex.RLock()
	conn, exists := m.connections[connID]
	m.connMutex.RUnlock()

	if !exists {
		return errors.New("connection not found")
	}

	_, err := conn.LocalConn.Write(data)
	if err != nil {
		return err
	}

	atomic.AddUint64(&conn.BytesRecv, uint64(len(data)))

	m.tunnelsMutex.RLock()
	tunnel, exists := m.tunnels[conn.TunnelID]
	m.tunnelsMutex.RUnlock()

	if exists {
		atomic.AddUint64(&tunnel.BytesRecv, uint64(len(data)))
		tunnel.LastActivity = time.Now()
	}

	return nil
}

// StopTunnel stops a tunnel
func (m *Manager) StopTunnel(id uint32) error {
	m.tunnelsMutex.RLock()
	tunnel, exists := m.tunnels[id]
	m.tunnelsMutex.RUnlock()

	if !exists {
		return errors.New("tunnel not found")
	}

	tunnel.mutex.Lock()
	defer tunnel.mutex.Unlock()

	close(tunnel.closed)

	if tunnel.listener != nil {
		tunnel.listener.Close()
	}

	tunnel.State = TunnelStateInactive
	return nil
}

// DeleteTunnel deletes a tunnel
func (m *Manager) DeleteTunnel(id uint32) error {
	m.StopTunnel(id)

	m.tunnelsMutex.Lock()
	delete(m.tunnels, id)
	m.tunnelsMutex.Unlock()

	return nil
}

// GetTunnel gets a tunnel by ID
func (m *Manager) GetTunnel(id uint32) *Tunnel {
	m.tunnelsMutex.RLock()
	defer m.tunnelsMutex.RUnlock()
	return m.tunnels[id]
}

// GetAllTunnels returns all tunnels
func (m *Manager) GetAllTunnels() []*Tunnel {
	m.tunnelsMutex.RLock()
	defer m.tunnelsMutex.RUnlock()

	tunnels := make([]*Tunnel, 0, len(m.tunnels))
	for _, t := range m.tunnels {
		tunnels = append(tunnels, t)
	}
	return tunnels
}

// SetDataCallback sets the callback for tunnel data
func (m *Manager) SetDataCallback(fn func(tunnelID uint32, connID uint32, data []byte) error) {
	m.onTunnelData = fn
}

// SetOpenCallback sets the callback for tunnel open
func (m *Manager) SetOpenCallback(fn func(tunnelID uint32, connID uint32) error) {
	m.onTunnelOpen = fn
}

// SetCloseCallback sets the callback for tunnel close
func (m *Manager) SetCloseCallback(fn func(tunnelID uint32, connID uint32) error) {
	m.onTunnelClose = fn
}

// Close closes the manager
func (m *Manager) Close() error {
	close(m.closed)

	m.tunnelsMutex.Lock()
	for _, tunnel := range m.tunnels {
		tunnel.mutex.Lock()
		close(tunnel.closed)
		if tunnel.listener != nil {
			tunnel.listener.Close()
		}
		tunnel.mutex.Unlock()
	}
	m.tunnelsMutex.Unlock()

	return nil
}

// Message types for RPFT protocol
const (
	RPFTMessageOpenTunnel  uint8 = 1
	RPFTMessageCloseTunnel uint8 = 2
	RPFTMessageOpenConn    uint8 = 3
	RPFTMessageCloseConn   uint8 = 4
	RPFTMessageData        uint8 = 5
	RPFTMessageAck         uint8 = 6
)

// RPFTMessage represents an RPFT control message
type RPFTMessage struct {
	Type     uint8
	TunnelID uint32
	ConnID   uint32
	Data     []byte
}

// Serialize serializes an RPFT message
func (msg *RPFTMessage) Serialize() []byte {
	buf := make([]byte, 9+len(msg.Data))
	buf[0] = msg.Type
	binary.LittleEndian.PutUint32(buf[1:5], msg.TunnelID)
	binary.LittleEndian.PutUint32(buf[5:9], msg.ConnID)
	copy(buf[9:], msg.Data)
	return buf
}

// ParseRPFTMessage parses an RPFT message from bytes
func ParseRPFTMessage(data []byte) (*RPFTMessage, error) {
	if len(data) < 9 {
		return nil, io.ErrShortBuffer
	}

	return &RPFTMessage{
		Type:     data[0],
		TunnelID: binary.LittleEndian.Uint32(data[1:5]),
		ConnID:   binary.LittleEndian.Uint32(data[5:9]),
		Data:     data[9:],
	}, nil
}

// Helper functions
func itoa(i int) string {
	return string(rune('0'+i/10000%10)) + string(rune('0'+i/1000%10)) +
		string(rune('0'+i/100%10)) + string(rune('0'+i/10%10)) + string(rune('0'+i%10))
}

func addrToConnID(addr *net.UDPAddr) uint32 {
	ip := addr.IP.To4()
	if ip == nil {
		ip = addr.IP.To16()[:4]
	}
	return binary.BigEndian.Uint32(ip) ^ uint32(addr.Port)
}
