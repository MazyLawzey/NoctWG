
package protocol

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/MazyLawzey/noctwg/core/crypto"
)

// Peer represents a VPN peer
type Peer struct {
	mutex sync.RWMutex

	// Identity
	PublicKey crypto.PublicKey

	// Endpoint
	Endpoint net.UDPAddr

	// Handshake state
	handshake *Handshake

	// Current session
	session atomic.Pointer[Session]

	// Signal channel for session establishment
	sessionReady chan struct{}

	// Pre-shared key
	PreSharedKey [crypto.KeySize]byte

	// Allowed IPs
	AllowedIPs []net.IPNet

	// Keep-alive interval
	PersistentKeepalive time.Duration

	// Timers
	lastHandshake        time.Time
	lastReceive          time.Time
	lastSend             time.Time
	lastHandshakeAttempt time.Time

	// Cached initiation packet for retry (resend same bytes)
	lastInitiationData []byte

	// RPFT tunnels for this peer
	RPFTTunnels []*RPFTTunnel

	// Traffic stats
	BytesSent     uint64
	BytesReceived uint64

	// State
	isRunning bool
}

// Device represents the NoctWG device
type Device struct {
	mutex sync.RWMutex

	// Our identity
	privateKey crypto.PrivateKey
	publicKey  crypto.PublicKey

	// Network
	conn     net.PacketConn
	port     uint16
	endpoint string

	// Peers
	peers    map[crypto.PublicKey]*Peer
	peersMux sync.RWMutex

	// Index table for quick lookup
	indexTable sync.Map // uint32 -> *Peer

	// TUN device (for full VPN mode)
	tunDevice io.ReadWriteCloser
	tunName   string

	// Message queues
	inbound    chan *InboundMessage
	outbound   chan *OutboundMessage
	tunPackets chan []byte // TUN -> encrypt workers

	// State
	state      atomic.Uint32
	closed     chan struct{}
	shutdownWg sync.WaitGroup

	// Logger
	logger Logger

	// RPFT handler (exported for external access)
	rpftHandler *RPFTHandler
}

// RPFTHandler returns the RPFT handler - note: actual method in exports.go
func (d *Device) rpftHandlerInternal() *RPFTHandler {
	return d.rpftHandler
}

// DeviceState represents device state
type DeviceState uint32

const (
	DeviceStateDown DeviceState = iota
	DeviceStateUp
	DeviceStateClosed
)

// InboundMessage represents a received message
type InboundMessage struct {
	Data     []byte
	Endpoint net.UDPAddr
	Peer     *Peer
}

// OutboundMessage represents a message to send
type OutboundMessage struct {
	Data     []byte
	Endpoint net.UDPAddr
	Peer     *Peer
}

// Logger interface for device logging
type Logger interface {
	Verbosef(format string, args ...interface{})
	Errorf(format string, args ...interface{})
}

// DefaultLogger is a simple logger implementation
type DefaultLogger struct {
	Prefix string
}

func (l *DefaultLogger) Verbosef(format string, args ...interface{}) {
	// fmt.Printf("[%s] "+format+"\n", append([]interface{}{l.Prefix}, args...)...)
}

func (l *DefaultLogger) Errorf(format string, args ...interface{}) {
	// fmt.Printf("[%s] ERROR: "+format+"\n", append([]interface{}{l.Prefix}, args...)...)
}

// NewDevice creates a new NoctWG device
func NewDevice(privateKey crypto.PrivateKey, logger Logger) (*Device, error) {
	if logger == nil {
		logger = &DefaultLogger{Prefix: "noctwg"}
	}

	pubKey, err := privateKey.PublicKey()
	if err != nil {
		return nil, err
	}

	d := &Device{
		privateKey: privateKey,
		publicKey:  pubKey,
		peers:      make(map[crypto.PublicKey]*Peer),
		inbound:    make(chan *InboundMessage, 1024),
		outbound:   make(chan *OutboundMessage, 1024),
		tunPackets: make(chan []byte, 1024),
		closed:     make(chan struct{}),
		logger:     logger,
	}

	d.rpftHandler = NewRPFTHandler(d)

	return d, nil
}

// Listen starts listening on the specified port
func (d *Device) Listen(port uint16) error {
	// Try IPv4 first, fallback to IPv6
	addr4 := &net.UDPAddr{IP: net.ParseIP("0.0.0.0"), Port: int(port)}
	fmt.Printf("[LISTEN] Attempting to create IPv4 socket on 0.0.0.0:%d\n", port)
	conn, err := net.ListenUDP("udp4", addr4)
	if err != nil {
		// Fallback to IPv6
		fmt.Printf("[LISTEN] IPv4 failed: %v, trying IPv6\n", err)
		addr6 := &net.UDPAddr{IP: net.ParseIP("::"), Port: int(port)}
		var err6 error
		conn, err6 = net.ListenUDP("udp6", addr6)
		if err6 != nil {
			return err // Return original error
		}
		fmt.Printf("[LISTEN] Using IPv6 on [::]: %d\n", port)
	} else {
		fmt.Printf("[LISTEN] Successfully bound to IPv4 0.0.0.0:%d\n", port)
	}

	d.conn = conn
	d.port = port

	// Set large UDP socket buffers to prevent kernel-side packet drops under load
	conn.SetReadBuffer(4 * 1024 * 1024)  // 4 MB
	conn.SetWriteBuffer(4 * 1024 * 1024) // 4 MB

	// Get actual port if 0 was specified
	if port == 0 {
		localAddr := conn.LocalAddr().(*net.UDPAddr)
		d.port = uint16(localAddr.Port)
	}

	fmt.Printf("[LISTEN] Listening on %s\n", conn.LocalAddr().String())

	d.state.Store(uint32(DeviceStateUp))

	// Start receive loop
	d.shutdownWg.Add(1)
	go d.receiveLoop()

	// Start send workers (parallel UDP writes)
	numWorkers := runtime.NumCPU()
	if numWorkers < 2 {
		numWorkers = 2
	}
	for i := 0; i < numWorkers; i++ {
		d.shutdownWg.Add(1)
		go d.sendLoop()
	}

	// Start inbound processing workers (parallel decryption)
	for i := 0; i < numWorkers; i++ {
		d.shutdownWg.Add(1)
		go d.processInbound()
	}

	return nil
}

// AddPeer adds a peer to the device
func (d *Device) AddPeer(publicKey crypto.PublicKey) (*Peer, error) {
	d.peersMux.Lock()
	defer d.peersMux.Unlock()

	if _, exists := d.peers[publicKey]; exists {
		return nil, errors.New("peer already exists")
	}

	peer := &Peer{
		PublicKey:    publicKey,
		handshake:    NewHandshake(d.privateKey, publicKey),
		sessionReady: make(chan struct{}),
	}

	d.peers[publicKey] = peer
	return peer, nil
}

// RemovePeer removes a peer from the device
func (d *Device) RemovePeer(publicKey crypto.PublicKey) {
	d.peersMux.Lock()
	defer d.peersMux.Unlock()

	if peer, exists := d.peers[publicKey]; exists {
		if session := peer.session.Load(); session != nil {
			session.Invalidate()
		}
		delete(d.peers, publicKey)
	}
}

// GetPeer retrieves a peer by public key
func (d *Device) GetPeer(publicKey crypto.PublicKey) *Peer {
	d.peersMux.RLock()
	defer d.peersMux.RUnlock()
	return d.peers[publicKey]
}

// receiveLoop receives packets from the network
func (d *Device) receiveLoop() {
	defer d.shutdownWg.Done()

	buf := make([]byte, 65536)
	for {
		select {
		case <-d.closed:
			return
		default:
		}

		n, addr, err := d.conn.ReadFrom(buf)
		if err != nil {
			if d.state.Load() == uint32(DeviceStateClosed) {
				return
			}
			fmt.Printf("[RECEIVE] Error reading from socket: %v\n", err)
			continue
		}

		if n < 4 {
			continue
		}

		// Copy packet data
		data := make([]byte, n)
		copy(data, buf[:n])

		udpAddr, ok := addr.(*net.UDPAddr)
		if !ok {
			continue
		}

		d.inbound <- &InboundMessage{
			Data:     data,
			Endpoint: *udpAddr,
		}
	}
}

// sendLoop sends packets to the network
func (d *Device) sendLoop() {
	defer d.shutdownWg.Done()

	for {
		select {
		case <-d.closed:
			return
		case msg := <-d.outbound:
			_, err := d.conn.WriteTo(msg.Data, &msg.Endpoint)
			if err != nil {
				d.logger.Errorf("send error: %v", err)
			}
		}
	}
}

// processInbound processes incoming messages
func (d *Device) processInbound() {
	defer d.shutdownWg.Done()

	for {
		select {
		case <-d.closed:
			return
		case msg := <-d.inbound:
			d.handleMessage(msg)
		}
	}
}

// handleMessage handles an incoming message
func (d *Device) handleMessage(msg *InboundMessage) {
	if len(msg.Data) < 4 {
		return
	}

	msgType := msg.Data[0]

	switch msgType {
	case MessageTypeInitiation:
		d.handleInitiation(msg)
	case MessageTypeResponse:
		d.handleResponse(msg)
	case MessageTypeTransport:
		d.handleTransport(msg)
	case MessageTypeRPFT:
		d.handleRPFT(msg)
	case MessageTypeRPFTData:
		d.handleRPFTData(msg)
	}
}

// handleInitiation handles a handshake initiation
func (d *Device) handleInitiation(msg *InboundMessage) {
	if len(msg.Data) < MessageInitiationSize {
		return
	}

	// Parse message
	initMsg := &MessageInitiation{
		Type: msg.Data[0],
	}
	initMsg.SenderIndex = binary.LittleEndian.Uint32(msg.Data[4:8])
	copy(initMsg.Ephemeral[:], msg.Data[8:40])
	copy(initMsg.EncryptedStatic[:], msg.Data[40:88])
	copy(initMsg.EncryptedTimestamp[:], msg.Data[88:116])
	copy(initMsg.MAC1[:], msg.Data[116:132])
	copy(initMsg.MAC2[:], msg.Data[132:148])

	// Create handshake for unknown peer
	handshake := NewHandshake(d.privateKey, crypto.PublicKey{})

	err := handshake.ConsumeInitiation(initMsg)
	if err != nil {
		d.logger.Errorf("failed to consume initiation: %v", err)
		return
	}

	// Find or create peer
	d.peersMux.Lock()
	peer, exists := d.peers[handshake.remoteStatic]
	if !exists {
		peer = &Peer{
			PublicKey:    handshake.remoteStatic,
			handshake:    handshake,
			sessionReady: make(chan struct{}),
		}
		d.peers[handshake.remoteStatic] = peer
	} else {
		peer.handshake = handshake
	}
	peer.Endpoint = msg.Endpoint
	d.peersMux.Unlock()

	// Create response
	response, session, err := handshake.CreateResponse()
	if err != nil {
		fmt.Printf("[INITIATION] CreateResponse failed: %v\n", err)
		d.logger.Errorf("failed to create response: %v", err)
		return
	}

	fmt.Printf("[INITIATION] Response created! SenderIndex=%d, ReceiverIndex=%d\n", response.SenderIndex, response.ReceiverIndex)

	// Store session
	peer.session.Store(session)
	peer.notifySessionReady()
	d.indexTable.Store(session.localIndex, peer)
	peer.lastHandshake = time.Now()

	// Send response
	respData := make([]byte, MessageResponseSize)
	respData[0] = response.Type
	binary.LittleEndian.PutUint32(respData[4:], response.SenderIndex)
	binary.LittleEndian.PutUint32(respData[8:], response.ReceiverIndex)
	copy(respData[12:44], response.Ephemeral[:])
	copy(respData[44:60], response.EncryptedNothing[:])
	copy(respData[60:76], response.MAC1[:])
	copy(respData[76:92], response.MAC2[:])

	fmt.Printf("[INITIATION] Sending response back to client (%d bytes)\n", len(respData))
	d.outbound <- &OutboundMessage{
		Data:     respData,
		Endpoint: msg.Endpoint,
		Peer:     peer,
	}
}

// handleResponse handles a handshake response
func (d *Device) handleResponse(msg *InboundMessage) {
	if len(msg.Data) < MessageResponseSize {
		fmt.Printf("[RESPONSE] Message too short: %d bytes\n", len(msg.Data))
		return
	}

	fmt.Printf("[RESPONSE] Received response message (%d bytes)\n", len(msg.Data))

	// Parse message
	respMsg := &MessageResponse{
		Type: msg.Data[0],
	}
	respMsg.SenderIndex = binary.LittleEndian.Uint32(msg.Data[4:8])
	respMsg.ReceiverIndex = binary.LittleEndian.Uint32(msg.Data[8:12])
	copy(respMsg.Ephemeral[:], msg.Data[12:44])
	copy(respMsg.EncryptedNothing[:], msg.Data[44:60])
	copy(respMsg.MAC1[:], msg.Data[60:76])
	copy(respMsg.MAC2[:], msg.Data[76:92])

	fmt.Printf("[RESPONSE] ReceiverIndex=%d\n", respMsg.ReceiverIndex)

	// Find peer by receiver index
	peerInterface, ok := d.indexTable.Load(respMsg.ReceiverIndex)
	if !ok {
		fmt.Printf("[RESPONSE] No peer found for receiver index %d\n", respMsg.ReceiverIndex)
		d.logger.Errorf("unknown receiver index: %d", respMsg.ReceiverIndex)
		return
	}
	peer := peerInterface.(*Peer)

	fmt.Printf("[RESPONSE] Found peer, consuming response...\n")
	// Consume response
	session, err := peer.handshake.ConsumeResponse(respMsg)
	if err != nil {
		fmt.Printf("[RESPONSE] ConsumeResponse failed: %v\n", err)
		d.logger.Errorf("failed to consume response: %v", err)
		return
	}

	// Store session
	peer.session.Store(session)
	peer.notifySessionReady()
	d.indexTable.Store(session.localIndex, peer)
	peer.lastHandshake = time.Now()
	peer.Endpoint = msg.Endpoint

	fmt.Printf("[RESPONSE] Session created! localIndex=%d, remoteIndex=%d\n", session.localIndex, session.remoteIndex)
	d.logger.Verbosef("handshake complete with peer %s", peer.PublicKey.ToBase64())
}

// handleTransport handles encrypted transport messages
func (d *Device) handleTransport(msg *InboundMessage) {
	if len(msg.Data) < MessageTransportHeaderSize+16 {
		return
	}

	receiverIndex := binary.LittleEndian.Uint32(msg.Data[4:8])

	// Find peer by receiver index
	peerInterface, ok := d.indexTable.Load(receiverIndex)
	if !ok {
		return
	}
	peer := peerInterface.(*Peer)

	session := peer.session.Load()
	if session == nil {
		return
	}

	// Decrypt
	plaintext, err := session.Decrypt(msg.Data)
	if err != nil {
		d.logger.Errorf("decrypt error: %v", err)
		return
	}

	peer.lastReceive = time.Now()
	atomic.AddUint64(&peer.BytesReceived, uint64(len(plaintext)))

	// Process decrypted packet
	if len(plaintext) > 0 {
		if len(plaintext) >= 20 {
			version := plaintext[0] >> 4
			if version == 4 {
				srcIP := net.IP(make([]byte, 4))
				copy(srcIP, plaintext[12:16])
				// Auto-learn source IP so return traffic finds this peer
				d.autoLearnAllowedIP(peer, srcIP)
			}
		}

		// If server has TUN device, write to it (kernel handles routing/NAT/ICMP)
		if d.tunDevice != nil {
			_, err := d.tunDevice.Write(plaintext)
			if err != nil {
				d.logger.Errorf("TUN write error: %v", err)
			}
		} else {
			// No TUN — fall back to built-in ICMP echo responder
			d.handleICMPEcho(peer, plaintext)
		}
	}
}

// handleRPFT handles RPFT control messages
func (d *Device) handleRPFT(msg *InboundMessage) {
	d.rpftHandler.HandleControl(msg)
}

// handleRPFTData handles RPFT data messages
func (d *Device) handleRPFTData(msg *InboundMessage) {
	d.rpftHandler.HandleData(msg)
}

// SendTo sends encrypted data to a peer
func (d *Device) SendTo(peer *Peer, data []byte) error {
	session := peer.session.Load()
	if session == nil {
		return errors.New("no session")
	}

	encrypted, err := session.Encrypt(data)
	if err != nil {
		return err
	}

	peer.lastSend = time.Now()
	atomic.AddUint64(&peer.BytesSent, uint64(len(data)))

	d.outbound <- &OutboundMessage{
		Data:     encrypted,
		Endpoint: peer.Endpoint,
		Peer:     peer,
	}

	return nil
}

// InitiateHandshake starts a handshake with a peer
func (d *Device) InitiateHandshake(peer *Peer) error {
	peer.mutex.Lock()
	defer peer.mutex.Unlock()

	// Reset session-ready channel so callers can wait on fresh handshake
	peer.sessionReady = make(chan struct{})

	peer.handshake = NewHandshake(d.privateKey, peer.PublicKey)

	initMsg, err := peer.handshake.CreateInitiation()
	if err != nil {
		return err
	}

	// Store index for response lookup
	d.indexTable.Store(initMsg.SenderIndex, peer)
	peer.lastHandshakeAttempt = time.Now()

	// Serialize message
	data := make([]byte, MessageInitiationSize)
	data[0] = initMsg.Type
	binary.LittleEndian.PutUint32(data[4:], initMsg.SenderIndex)
	copy(data[8:40], initMsg.Ephemeral[:])
	copy(data[40:88], initMsg.EncryptedStatic[:])
	copy(data[88:116], initMsg.EncryptedTimestamp[:])
	copy(data[116:132], initMsg.MAC1[:])
	copy(data[132:148], initMsg.MAC2[:])

	// Cache for retries
	peer.lastInitiationData = make([]byte, len(data))
	copy(peer.lastInitiationData, data)

	d.outbound <- &OutboundMessage{
		Data:     data,
		Endpoint: peer.Endpoint,
		Peer:     peer,
	}

	return nil
}

// resendInitiation resends the cached initiation packet without creating a new handshake.
// This preserves the handshake state so the server's response to any copy can be consumed.
func (d *Device) resendInitiation(peer *Peer) {
	peer.mutex.RLock()
	data := peer.lastInitiationData
	endpoint := peer.Endpoint
	peer.mutex.RUnlock()

	if data == nil {
		fmt.Printf("[HANDSHAKE] No cached initiation to resend\n")
		return
	}

	d.outbound <- &OutboundMessage{
		Data:     data,
		Endpoint: endpoint,
		Peer:     peer,
	}
}

// InitiateHandshakeWithRetry starts a handshake with retries until session is
// established or all attempts are exhausted.  Returns the established session.
func (d *Device) InitiateHandshakeWithRetry(peer *Peer, attempts int, timeout time.Duration) (*Session, error) {
	// Create handshake once
	fmt.Printf("[HANDSHAKE] Starting handshake (%d attempts, %v timeout each)\n", attempts, timeout)

	if err := d.InitiateHandshake(peer); err != nil {
		return nil, fmt.Errorf("initiate handshake: %w", err)
	}

	for i := 0; i < attempts; i++ {
		if i > 0 {
			// Resend the same packet (same ephemeral key, same SenderIndex)
			fmt.Printf("[HANDSHAKE] Resending initiation (attempt %d/%d)\n", i+1, attempts)
			d.resendInitiation(peer)
		} else {
			fmt.Printf("[HANDSHAKE] Waiting for response (attempt %d/%d)\n", i+1, attempts)
		}

		session, err := peer.WaitForSession(timeout)
		if err == nil && session != nil {
			fmt.Printf("[HANDSHAKE] Session established on attempt %d\n", i+1)
			return session, nil
		}

		fmt.Printf("[HANDSHAKE] Attempt %d/%d timed out\n", i+1, attempts)
	}

	return nil, fmt.Errorf("handshake failed after %d attempts (no response from server — check firewall/NAT)", attempts)
}

// Close shuts down the device
func (d *Device) Close() error {
	if !d.state.CompareAndSwap(uint32(DeviceStateUp), uint32(DeviceStateClosed)) {
		return nil
	}

	close(d.closed)

	if d.conn != nil {
		d.conn.Close()
	}

	if d.tunDevice != nil {
		d.tunDevice.Close()
	}

	d.shutdownWg.Wait()
	return nil
}

// GetPublicKey returns the device's public key
func (d *Device) GetPublicKey() *crypto.PublicKey {
	return &d.publicKey
}

// GetPort returns the listening port
func (d *Device) GetPort() uint16 {
	return d.port
}

// SetEndpoint sets a peer's endpoint
func (p *Peer) SetEndpoint(addr string) error {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return err
	}
	p.Endpoint = *udpAddr
	return nil
}

// AddAllowedIP adds an allowed IP range for a peer
func (p *Peer) AddAllowedIP(cidr string) error {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return err
	}
	p.AllowedIPs = append(p.AllowedIPs, *ipnet)
	return nil
}

// GetSession returns the current session
func (p *Peer) GetSession() *Session {
	return p.session.Load()
}

// WaitForSession waits until a session is established or timeout expires.
// Returns the session or an error on timeout.
func (p *Peer) WaitForSession(timeout time.Duration) (*Session, error) {
	// Check if session already exists
	if s := p.session.Load(); s != nil {
		return s, nil
	}

	select {
	case <-p.sessionReady:
		s := p.session.Load()
		if s != nil {
			return s, nil
		}
		return nil, errors.New("session signaled but not available")
	case <-time.After(timeout):
		// One last check
		if s := p.session.Load(); s != nil {
			return s, nil
		}
		return nil, errors.New("handshake timeout: no session established")
	}
}

// notifySessionReady signals that a session has been established.
// Safe to call multiple times.
func (p *Peer) notifySessionReady() {
	select {
	case <-p.sessionReady:
		// Already closed / signaled — nothing to do
	default:
		close(p.sessionReady)
	}
}

// SetTUN sets the TUN device for the VPN
func (d *Device) SetTUN(tunDevice io.ReadWriteCloser, name string) {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	d.tunDevice = tunDevice
	d.tunName = name
}

// GetTUN returns the TUN device
func (d *Device) GetTUN() io.ReadWriteCloser {
	d.mutex.RLock()
	defer d.mutex.RUnlock()
	return d.tunDevice
}

// StartTUNLoop starts the TUN read/write loops
func (d *Device) StartTUNLoop() error {
	if d.tunDevice == nil {
		return errors.New("TUN device not set")
	}

	// TUN -> Peers (encrypt and send)
	// Single reader goroutine feeds packets into channel
	d.shutdownWg.Add(1)
	go d.tunReadLoop()

	// Multiple encrypt workers pick up TUN packets and encrypt+send in parallel
	numWorkers := runtime.NumCPU()
	if numWorkers < 2 {
		numWorkers = 2
	}
	for i := 0; i < numWorkers; i++ {
		d.shutdownWg.Add(1)
		go d.tunEncryptWorker()
	}

	return nil
}

// tunReadLoop reads from TUN and dispatches to encrypt workers
func (d *Device) tunReadLoop() {
	defer d.shutdownWg.Done()

	for {
		// Allocate per-read buffer so workers own their slice
		buf := make([]byte, 1500)

		n, err := d.tunDevice.Read(buf)
		if err != nil {
			if err == io.EOF {
				return
			}
			select {
			case <-d.closed:
				return
			default:
			}
			d.logger.Errorf("TUN read error: %v", err)
			continue
		}

		if n < 20 {
			continue
		}

		// Drop IPv6 silently
		if buf[0]>>4 == 6 {
			continue
		}

		select {
		case d.tunPackets <- buf[:n]:
		case <-d.closed:
			return
		}
	}
}

// tunEncryptWorker picks up TUN packets, encrypts, and sends
func (d *Device) tunEncryptWorker() {
	defer d.shutdownWg.Done()

	for {
		select {
		case <-d.closed:
			return
		case packet := <-d.tunPackets:
			peer := d.findPeerByDestIP(packet)
			if peer == nil {
				continue
			}

			session := peer.session.Load()
			if session == nil {
				peer.mutex.RLock()
				timeSinceLast := time.Since(peer.lastHandshakeAttempt)
				peer.mutex.RUnlock()

				if timeSinceLast > 5*time.Second {
					go func() {
						if err := d.InitiateHandshake(peer); err != nil {
							d.logger.Errorf("handshake initiation failed: %v", err)
						}
					}()
				}
				continue
			}

			encrypted, err := session.Encrypt(packet)
			if err != nil {
				d.logger.Errorf("encrypt error: %v", err)
				continue
			}

			d.outbound <- &OutboundMessage{
				Data:     encrypted,
				Endpoint: peer.Endpoint,
				Peer:     peer,
			}
		}
	}
}

// WriteTUN writes a packet to the TUN device
func (d *Device) WriteTUN(packet []byte) error {
	if d.tunDevice == nil {
		return errors.New("TUN device not set")
	}
	_, err := d.tunDevice.Write(packet)
	return err
}

// findPeerByDestIP finds a peer by destination IP in packet
func (d *Device) findPeerByDestIP(packet []byte) *Peer {
	if len(packet) < 20 {
		return nil
	}

	var destIP net.IP
	version := packet[0] >> 4

	if version == 4 {
		destIP = net.IP(packet[16:20])
	} else if version == 6 && len(packet) >= 40 {
		destIP = net.IP(packet[24:40])
	} else {
		return nil
	}

	d.peersMux.RLock()
	defer d.peersMux.RUnlock()

	// First try matching by AllowedIPs
	for _, peer := range d.peers {
		for _, allowedIP := range peer.AllowedIPs {
			if allowedIP.Contains(destIP) {
				return peer
			}
		}
	}

	// Fallback: if there's only one peer, use it (common for client mode)
	if len(d.peers) == 1 {
		for _, peer := range d.peers {
			return peer
		}
	}

	return nil
}

// autoLearnAllowedIP automatically adds source IP/32 to peer's AllowedIPs
// This enables return traffic routing for dynamically created peers
func (d *Device) autoLearnAllowedIP(peer *Peer, srcIP net.IP) {
	// Check if already known
	peer.mutex.RLock()
	for _, aip := range peer.AllowedIPs {
		if aip.Contains(srcIP) {
			peer.mutex.RUnlock()
			return
		}
	}
	peer.mutex.RUnlock()

	// Add /32 for IPv4, /128 for IPv6
	ones := 32
	if srcIP.To4() == nil {
		ones = 128
	}

	cidr := fmt.Sprintf("%s/%d", srcIP.String(), ones)
	peer.mutex.Lock()
	_, ipnet, err := net.ParseCIDR(cidr)
	if err == nil {
		peer.AllowedIPs = append(peer.AllowedIPs, *ipnet)
		fmt.Printf("[TRANSPORT] Auto-learned AllowedIP %s for peer\n", cidr)
	}
	peer.mutex.Unlock()
}

// handleICMPEcho responds to ICMP echo requests (ping)
func (d *Device) handleICMPEcho(peer *Peer, packet []byte) {
	if len(packet) < 20 {
		return
	}

	version := packet[0] >> 4
	fmt.Printf("[ICMP] Got packet, version=%d\n", version)

	if version != 4 {
		return // Only handle IPv4 for now
	}

	// Check if it's ICMP (protocol 1)
	protocol := packet[9]
	fmt.Printf("[ICMP] Protocol=%d\n", protocol)
	if protocol != 1 {
		return
	}

	// Check if it's echo request (type 8)
	if len(packet) < 20 {
		return
	}

	icmpType := packet[20]
	fmt.Printf("[ICMP] Type=%d\n", icmpType)
	if icmpType != 8 {
		return
	}

	fmt.Printf("[ICMP] Echo request detected! Creating reply...\n")

	// Create echo reply (swap source and destination IPs)
	response := make([]byte, len(packet))
	copy(response, packet)

	// Swap IPs
	copy(response[12:16], packet[16:20]) // Dest -> Source
	copy(response[16:20], packet[12:16]) // Source -> Dest

	// Change type from echo request (8) to echo reply (0)
	response[20] = 0

	// Recalculate IP checksum
	response[10] = 0
	response[11] = 0
	checksum := calculateChecksum(response[:20])
	binary.BigEndian.PutUint16(response[10:12], checksum)

	// Recalculate ICMP checksum
	response[22] = 0
	response[23] = 0
	checksum = calculateChecksum(response[20:])
	binary.BigEndian.PutUint16(response[22:24], checksum)

	fmt.Printf("[ICMP] Sending echo reply back to peer\n")
	// Send response back to peer
	d.SendTo(peer, response)
}

// calculateChecksum calculates IP/ICMP checksum
func calculateChecksum(data []byte) uint16 {
	sum := uint32(0)

	// Add up 16-bit words
	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(data[i])<<8 | uint32(data[i+1])
	}

	// Add remaining byte if odd length
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}

	// Fold 32-bit sum to 16 bits
	for sum>>16 > 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}

	// Return one's complement
	return ^uint16(sum)
}
