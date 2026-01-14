/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2025 NoctWG. All Rights Reserved.
 */

package protocol

import (
	"encoding/binary"
	"sync"

	"github.com/noctwg/noctwg/rpft"
)

// RPFTHandler handles RPFT messages within the VPN protocol
type RPFTHandler struct {
	device  *Device
	manager *rpft.Manager
	mutex   sync.RWMutex
}

// RPFTTunnel represents an RPFT tunnel associated with a peer
type RPFTTunnel struct {
	ID         uint32
	Tunnel     *rpft.Tunnel
	PeerPubKey string
}

// NewRPFTHandler creates a new RPFT handler
func NewRPFTHandler(device *Device) *RPFTHandler {
	h := &RPFTHandler{
		device:  device,
		manager: rpft.NewManager(),
	}

	// Set up callbacks
	h.manager.SetDataCallback(h.onData)
	h.manager.SetOpenCallback(h.onOpen)
	h.manager.SetCloseCallback(h.onClose)

	return h
}

// CreateTunnel creates a new RPFT tunnel for a peer
func (h *RPFTHandler) CreateTunnel(peer *Peer, config rpft.TunnelConfig) (*rpft.Tunnel, error) {
	tunnel, err := h.manager.CreateTunnel(config)
	if err != nil {
		return nil, err
	}

	peer.mutex.Lock()
	peer.RPFTTunnels = append(peer.RPFTTunnels, &RPFTTunnel{
		ID:         tunnel.ID,
		Tunnel:     tunnel,
		PeerPubKey: peer.PublicKey.ToBase64(),
	})
	peer.mutex.Unlock()

	return tunnel, nil
}

// StartTunnel starts an RPFT tunnel
func (h *RPFTHandler) StartTunnel(tunnelID uint32) error {
	return h.manager.StartTunnel(tunnelID)
}

// StopTunnel stops an RPFT tunnel
func (h *RPFTHandler) StopTunnel(tunnelID uint32) error {
	return h.manager.StopTunnel(tunnelID)
}

// HandleControl handles RPFT control messages
func (h *RPFTHandler) HandleControl(msg *InboundMessage) {
	if len(msg.Data) < MessageRPFTHeaderSize {
		return
	}

	rpftMsg, err := rpft.ParseRPFTMessage(msg.Data[4:])
	if err != nil {
		return
	}

	switch rpftMsg.Type {
	case rpft.RPFTMessageOpenTunnel:
		h.handleOpenTunnel(msg, rpftMsg)
	case rpft.RPFTMessageCloseTunnel:
		h.handleCloseTunnel(msg, rpftMsg)
	case rpft.RPFTMessageOpenConn:
		h.handleOpenConn(msg, rpftMsg)
	case rpft.RPFTMessageCloseConn:
		h.handleCloseConn(msg, rpftMsg)
	}
}

// HandleData handles RPFT data messages
func (h *RPFTHandler) HandleData(msg *InboundMessage) {
	if len(msg.Data) < MessageRPFTHeaderSize {
		return
	}

	rpftMsg, err := rpft.ParseRPFTMessage(msg.Data[4:])
	if err != nil {
		return
	}

	// Write data to the local connection
	h.manager.WriteToConnection(rpftMsg.ConnID, rpftMsg.Data)
}

// handleOpenTunnel handles a request to open a tunnel
func (h *RPFTHandler) handleOpenTunnel(msg *InboundMessage, rpftMsg *rpft.RPFTMessage) {
	// Parse tunnel config from message data
	if len(rpftMsg.Data) < 6 {
		return
	}

	tunnelType := rpft.TunnelType(rpftMsg.Data[0])
	protocol := rpft.TunnelProtocol(rpftMsg.Data[1])
	localPort := binary.LittleEndian.Uint16(rpftMsg.Data[2:4])
	remotePort := binary.LittleEndian.Uint16(rpftMsg.Data[4:6])

	config := rpft.TunnelConfig{
		Type:       tunnelType,
		Protocol:   protocol,
		LocalPort:  localPort,
		RemotePort: remotePort,
	}

	tunnel, err := h.manager.CreateTunnel(config)
	if err != nil {
		return
	}

	h.manager.StartTunnel(tunnel.ID)

	// Send acknowledgment
	h.sendAck(msg, rpftMsg.TunnelID, tunnel.ID)
}

// handleCloseTunnel handles a request to close a tunnel
func (h *RPFTHandler) handleCloseTunnel(msg *InboundMessage, rpftMsg *rpft.RPFTMessage) {
	h.manager.StopTunnel(rpftMsg.TunnelID)
}

// handleOpenConn handles a new connection on a tunnel
func (h *RPFTHandler) handleOpenConn(msg *InboundMessage, rpftMsg *rpft.RPFTMessage) {
	// Handle remote connection open
}

// handleCloseConn handles a connection close on a tunnel
func (h *RPFTHandler) handleCloseConn(msg *InboundMessage, rpftMsg *rpft.RPFTMessage) {
	// Handle remote connection close
}

// sendAck sends an acknowledgment message
func (h *RPFTHandler) sendAck(msg *InboundMessage, requestID, tunnelID uint32) {
	ack := &rpft.RPFTMessage{
		Type:     rpft.RPFTMessageAck,
		TunnelID: tunnelID,
		ConnID:   requestID,
	}

	data := make([]byte, 4+len(ack.Serialize()))
	data[0] = MessageTypeRPFT
	copy(data[4:], ack.Serialize())

	h.device.outbound <- &OutboundMessage{
		Data:     data,
		Endpoint: msg.Endpoint,
	}
}

// onData callback for tunnel data
func (h *RPFTHandler) onData(tunnelID uint32, connID uint32, data []byte) error {
	tunnel := h.manager.GetTunnel(tunnelID)
	if tunnel == nil {
		return nil
	}

	// Find peer for this tunnel
	var peer *Peer
	h.device.peersMux.RLock()
	for _, p := range h.device.peers {
		for _, t := range p.RPFTTunnels {
			if t.ID == tunnelID {
				peer = p
				break
			}
		}
		if peer != nil {
			break
		}
	}
	h.device.peersMux.RUnlock()

	if peer == nil {
		return nil
	}

	// Send data through VPN
	rpftMsg := &rpft.RPFTMessage{
		Type:     rpft.RPFTMessageData,
		TunnelID: tunnelID,
		ConnID:   connID,
		Data:     data,
	}

	msgData := make([]byte, 4+len(rpftMsg.Serialize()))
	msgData[0] = MessageTypeRPFTData
	copy(msgData[4:], rpftMsg.Serialize())

	return h.device.SendTo(peer, msgData)
}

// onOpen callback for connection open
func (h *RPFTHandler) onOpen(tunnelID uint32, connID uint32) error {
	tunnel := h.manager.GetTunnel(tunnelID)
	if tunnel == nil {
		return nil
	}

	// Find peer and notify about connection
	var peer *Peer
	h.device.peersMux.RLock()
	for _, p := range h.device.peers {
		for _, t := range p.RPFTTunnels {
			if t.ID == tunnelID {
				peer = p
				break
			}
		}
		if peer != nil {
			break
		}
	}
	h.device.peersMux.RUnlock()

	if peer == nil {
		return nil
	}

	rpftMsg := &rpft.RPFTMessage{
		Type:     rpft.RPFTMessageOpenConn,
		TunnelID: tunnelID,
		ConnID:   connID,
	}

	msgData := make([]byte, 4+len(rpftMsg.Serialize()))
	msgData[0] = MessageTypeRPFT
	copy(msgData[4:], rpftMsg.Serialize())

	return h.device.SendTo(peer, msgData)
}

// onClose callback for connection close
func (h *RPFTHandler) onClose(tunnelID uint32, connID uint32) error {
	tunnel := h.manager.GetTunnel(tunnelID)
	if tunnel == nil {
		return nil
	}

	// Find peer and notify about connection close
	var peer *Peer
	h.device.peersMux.RLock()
	for _, p := range h.device.peers {
		for _, t := range p.RPFTTunnels {
			if t.ID == tunnelID {
				peer = p
				break
			}
		}
		if peer != nil {
			break
		}
	}
	h.device.peersMux.RUnlock()

	if peer == nil {
		return nil
	}

	rpftMsg := &rpft.RPFTMessage{
		Type:     rpft.RPFTMessageCloseConn,
		TunnelID: tunnelID,
		ConnID:   connID,
	}

	msgData := make([]byte, 4+len(rpftMsg.Serialize()))
	msgData[0] = MessageTypeRPFT
	copy(msgData[4:], rpftMsg.Serialize())

	return h.device.SendTo(peer, msgData)
}

// GetManager returns the RPFT manager
func (h *RPFTHandler) GetManager() *rpft.Manager {
	return h.manager
}

// Close closes the RPFT handler
func (h *RPFTHandler) Close() error {
	return h.manager.Close()
}
