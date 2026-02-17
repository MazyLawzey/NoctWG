
package protocol

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/blake2s"

	"github.com/MazyLawzey/noctwg/core/crypto"
)

// Noise Protocol construction identifier
const (
	NoiseConstruction = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
	NoctWGIdentifier  = "NoctWG v1"
	LabelMAC1         = "mac1----"
	LabelCookie       = "cookie--"
)

// Message types
const (
	MessageTypeUnknown     uint8 = 0
	MessageTypeInitiation  uint8 = 1
	MessageTypeResponse    uint8 = 2
	MessageTypeCookieReply uint8 = 3
	MessageTypeTransport   uint8 = 4
	MessageTypeRPFT        uint8 = 5 // RPFT control message
	MessageTypeRPFTData    uint8 = 6 // RPFT data message
)

// Message sizes
const (
	MessageInitiationSize      = 148
	MessageResponseSize        = 92
	MessageCookieReplySize     = 64
	MessageTransportHeaderSize = 16
	MessageRPFTHeaderSize      = 24
)

// HandshakeState represents the state of a handshake
type HandshakeState int

const (
	HandshakeZeroed HandshakeState = iota
	HandshakeInitiationCreated
	HandshakeInitiationConsumed
	HandshakeResponseCreated
	HandshakeResponseConsumed
)

// Handshake represents a noise handshake state
type Handshake struct {
	mutex sync.RWMutex
	state HandshakeState

	// Handshake hash
	hash     [blake2s.Size]byte
	chainKey [blake2s.Size]byte

	// Ephemeral keys
	localEphemeral  crypto.PrivateKey
	remoteEphemeral crypto.PublicKey

	// Static keys
	localStatic  crypto.PrivateKey
	remoteStatic crypto.PublicKey

	// Pre-shared key
	preSharedKey [crypto.KeySize]byte

	// Sender index
	localIndex  uint32
	remoteIndex uint32

	// Timestamps
	lastInitiation time.Time
	lastResponse   time.Time
}

// Session represents an established crypto session
type Session struct {
	// Local and remote indices
	localIndex  uint32
	remoteIndex uint32

	// Encryption keys
	sendKey    []byte
	receiveKey []byte

	// Cached AEAD ciphers — created once, reused for every packet
	// ChaCha20-Poly1305 is safe for concurrent use
	sendAEAD    *crypto.AEAD
	receiveAEAD *crypto.AEAD

	// Nonce counter — atomic, no mutex needed
	sendNonce atomic.Uint64

	// Replay protection (has its own mutex)
	replayFilter ReplayFilter

	// Session creation time
	created time.Time

	// Is this session valid?
	valid atomic.Bool
}

// ReplayFilter provides replay attack protection
type ReplayFilter struct {
	mutex   sync.Mutex
	bitmap  [512]bool
	counter uint64
}

// MessageInitiation is the first handshake message
type MessageInitiation struct {
	Type               uint8
	Reserved           [3]byte
	SenderIndex        uint32
	Ephemeral          [crypto.KeySize]byte
	EncryptedStatic    [crypto.KeySize + 16]byte // 16 = poly1305 tag
	EncryptedTimestamp [12 + 16]byte             // TAI64N timestamp
	MAC1               [16]byte
	MAC2               [16]byte
}

// MessageResponse is the handshake response
type MessageResponse struct {
	Type             uint8
	Reserved         [3]byte
	SenderIndex      uint32
	ReceiverIndex    uint32
	Ephemeral        [crypto.KeySize]byte
	EncryptedNothing [16]byte // empty encrypted message
	MAC1             [16]byte
	MAC2             [16]byte
}

// MessageCookieReply is sent when under load
type MessageCookieReply struct {
	Type            uint8
	Reserved        [3]byte
	ReceiverIndex   uint32
	Nonce           [24]byte
	EncryptedCookie [16 + 16]byte
}

// MessageTransport carries encrypted data
type MessageTransport struct {
	Type          uint8
	Reserved      [3]byte
	ReceiverIndex uint32
	Counter       uint64
	// Followed by encrypted payload
}

// NewHandshake creates a new handshake state
func NewHandshake(localStatic crypto.PrivateKey, remoteStatic crypto.PublicKey) *Handshake {
	h := &Handshake{
		localStatic:  localStatic,
		remoteStatic: remoteStatic,
		state:        HandshakeZeroed,
	}
	h.initialize()
	return h
}

// initialize sets up the initial handshake state
func (h *Handshake) initialize() {
	// Initialize with construction hash
	h.hash = crypto.Hash([]byte(NoiseConstruction))
	h.chainKey = crypto.Hash([]byte(NoiseConstruction))

	// Mix in identifier
	h.hash = crypto.MixHash(h.hash, []byte(NoctWGIdentifier))
}

// CreateInitiation creates a handshake initiation message
func (h *Handshake) CreateInitiation() (*MessageInitiation, error) {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	// Generate ephemeral key
	ephemeral, err := crypto.GeneratePrivateKey()
	if err != nil {
		return nil, err
	}
	h.localEphemeral = ephemeral

	ephemeralPub, err := ephemeral.PublicKey()
	if err != nil {
		return nil, err
	}

	msg := &MessageInitiation{
		Type: MessageTypeInitiation,
	}

	// Generate sender index
	indexBytes, err := crypto.GenerateRandomBytes(4)
	if err != nil {
		return nil, err
	}
	h.localIndex = binary.LittleEndian.Uint32(indexBytes)
	msg.SenderIndex = h.localIndex

	// Copy ephemeral public key
	copy(msg.Ephemeral[:], ephemeralPub[:])

	// Mix in ephemeral key
	h.hash = crypto.MixHash(h.hash, ephemeralPub[:])

	// Compute shared secret with remote static
	ss, err := ephemeral.SharedSecret(h.remoteStatic)
	if err != nil {
		return nil, err
	}

	// Derive keys
	newChainKey, key, err := crypto.MixKey(h.chainKey[:], ss)
	if err != nil {
		return nil, err
	}
	copy(h.chainKey[:], newChainKey)

	// Encrypt our static key
	aead, err := crypto.NewAEAD(key)
	if err != nil {
		return nil, err
	}

	localStaticPub, err := h.localStatic.PublicKey()
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, 12)
	encrypted := aead.Seal(nonce, localStaticPub[:], h.hash[:])
	copy(msg.EncryptedStatic[:], encrypted)

	h.hash = crypto.MixHash(h.hash, encrypted)

	// Compute shared secret with our static and their static
	ss, err = h.localStatic.SharedSecret(h.remoteStatic)
	if err != nil {
		return nil, err
	}

	newChainKey, key, err = crypto.MixKey(h.chainKey[:], ss)
	if err != nil {
		return nil, err
	}
	copy(h.chainKey[:], newChainKey)

	// Encrypt timestamp
	aead, err = crypto.NewAEAD(key)
	if err != nil {
		return nil, err
	}

	timestamp := createTimestamp()
	nonce = make([]byte, 12)
	binary.LittleEndian.PutUint64(nonce, 1)
	encrypted = aead.Seal(nonce, timestamp, h.hash[:])
	copy(msg.EncryptedTimestamp[:], encrypted)

	h.hash = crypto.MixHash(h.hash, encrypted)

	// Compute MAC1
	mac1Key := crypto.Hash(append([]byte(LabelMAC1), h.remoteStatic[:]...))
	mac1Data := make([]byte, 116) // Message up to MAC1 field
	mac1Data[0] = MessageTypeInitiation
	binary.LittleEndian.PutUint32(mac1Data[4:], msg.SenderIndex)
	copy(mac1Data[8:], msg.Ephemeral[:])
	copy(mac1Data[40:], msg.EncryptedStatic[:])
	copy(mac1Data[88:], msg.EncryptedTimestamp[:])

	mac1, err := crypto.HMAC(mac1Key[:], mac1Data)
	if err != nil {
		return nil, err
	}

	// Debug logging
	remoteStaticPub := h.remoteStatic
	fmt.Printf("[DEBUG] MAC1 Creation (Client):\n")
	fmt.Printf("  Remote Static (pub): %s\n", hex.EncodeToString(remoteStaticPub[:]))
	fmt.Printf("  MAC1 Key: %s\n", hex.EncodeToString(mac1Key[:16])) // First 16 bytes only
	fmt.Printf("  Generated MAC1: %s\n", hex.EncodeToString(mac1[:16]))
	fmt.Printf("  Ephemeral: %s\n", hex.EncodeToString(msg.Ephemeral[:]))
	fmt.Printf("  SenderIndex: %d\n", msg.SenderIndex)
	fmt.Printf("  MAC1Data (first 32 bytes): %s\n", hex.EncodeToString(mac1Data[:32]))

	copy(msg.MAC1[:], mac1[:16])

	h.state = HandshakeInitiationCreated
	h.lastInitiation = time.Now()

	return msg, nil
}

// ConsumeInitiation processes a received initiation message
func (h *Handshake) ConsumeInitiation(msg *MessageInitiation) error {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	if msg.Type != MessageTypeInitiation {
		return errors.New("invalid message type")
	}

	// Verify MAC1 - uses local PUBLIC key (receiver's public key)
	localPub, err := h.localStatic.PublicKey()
	if err != nil {
		return err
	}
	mac1Key := crypto.Hash(append([]byte(LabelMAC1), localPub[:]...))

	mac1Data := make([]byte, 116)
	mac1Data[0] = MessageTypeInitiation
	binary.LittleEndian.PutUint32(mac1Data[4:], msg.SenderIndex)
	copy(mac1Data[8:], msg.Ephemeral[:])
	copy(mac1Data[40:], msg.EncryptedStatic[:])
	copy(mac1Data[88:], msg.EncryptedTimestamp[:])

	expectedMAC1, err := crypto.HMAC(mac1Key[:], mac1Data)
	if err != nil {
		return err
	}

	// Debug logging - COMPREHENSIVE
	fmt.Printf("[DEBUG] MAC1 Verification (Server):\n")
	fmt.Printf("  Local Static (pub): %s\n", localPub.ToBase64())
	fmt.Printf("  MAC1 Key: %s\n", hex.EncodeToString(mac1Key[:]))
	fmt.Printf("  Received MAC1: %s\n", hex.EncodeToString(msg.MAC1[:]))
	fmt.Printf("  Expected MAC1: %s\n", hex.EncodeToString(expectedMAC1[:16])) // Only first 16 bytes!
	fmt.Printf("  Ephemeral: %s\n", hex.EncodeToString(msg.Ephemeral[:]))
	fmt.Printf("  SenderIndex: %d\n", msg.SenderIndex)
	fmt.Printf("  EncryptedStatic: %s\n", hex.EncodeToString(msg.EncryptedStatic[:]))
	fmt.Printf("  EncryptedTimestamp: %s\n", hex.EncodeToString(msg.EncryptedTimestamp[:]))
	fmt.Printf("  MAC1Data (first 32 bytes): %s\n", hex.EncodeToString(mac1Data[:32]))

	// Constant-time compare MAC1
	var mismatch byte
	for i := 0; i < 16; i++ {
		mismatch |= msg.MAC1[i] ^ expectedMAC1[i]
	}
	if mismatch != 0 {
		fmt.Printf("[DEBUG] MAC1 MISMATCH!\n")
		fmt.Printf("[DEBUG] Byte-by-byte comparison:\n")
		for i := 0; i < 16; i++ {
			fmt.Printf("  Byte %2d: Received=%02x  Expected=%02x  Match=%v\n", i, msg.MAC1[i], expectedMAC1[i], msg.MAC1[i] == expectedMAC1[i])
		}
		return errors.New("invalid MAC1")
	}
	fmt.Printf("[DEBUG] MAC1 verification SUCCESS!\n")

	// Store remote ephemeral
	copy(h.remoteEphemeral[:], msg.Ephemeral[:])
	h.remoteIndex = msg.SenderIndex

	// Mix in ephemeral
	h.hash = crypto.MixHash(h.hash, msg.Ephemeral[:])

	// Compute shared secret
	ss, err := h.localStatic.SharedSecret(h.remoteEphemeral)
	if err != nil {
		return err
	}

	newChainKey, key, err := crypto.MixKey(h.chainKey[:], ss)
	if err != nil {
		return err
	}
	copy(h.chainKey[:], newChainKey)

	// Decrypt static key
	aead, err := crypto.NewAEAD(key)
	if err != nil {
		return err
	}

	nonce := make([]byte, 12)
	decrypted, err := aead.Open(nonce, msg.EncryptedStatic[:], h.hash[:])
	if err != nil {
		return errors.New("failed to decrypt static key")
	}
	copy(h.remoteStatic[:], decrypted)

	h.hash = crypto.MixHash(h.hash, msg.EncryptedStatic[:])

	// Compute shared secret with their static
	ss, err = h.localStatic.SharedSecret(h.remoteStatic)
	if err != nil {
		return err
	}

	newChainKey, key, err = crypto.MixKey(h.chainKey[:], ss)
	if err != nil {
		return err
	}
	copy(h.chainKey[:], newChainKey)

	// Decrypt timestamp
	aead, err = crypto.NewAEAD(key)
	if err != nil {
		return err
	}

	nonce = make([]byte, 12)
	binary.LittleEndian.PutUint64(nonce, 1)
	_, err = aead.Open(nonce, msg.EncryptedTimestamp[:], h.hash[:])
	if err != nil {
		return errors.New("failed to decrypt timestamp")
	}

	h.hash = crypto.MixHash(h.hash, msg.EncryptedTimestamp[:])
	h.state = HandshakeInitiationConsumed

	return nil
}

// CreateResponse creates a handshake response message
func (h *Handshake) CreateResponse() (*MessageResponse, *Session, error) {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	if h.state != HandshakeInitiationConsumed {
		return nil, nil, errors.New("invalid handshake state")
	}

	// Generate ephemeral key
	ephemeral, err := crypto.GeneratePrivateKey()
	if err != nil {
		return nil, nil, err
	}
	h.localEphemeral = ephemeral

	ephemeralPub, err := ephemeral.PublicKey()
	if err != nil {
		return nil, nil, err
	}

	msg := &MessageResponse{
		Type: MessageTypeResponse,
	}

	// Generate sender index
	indexBytes, err := crypto.GenerateRandomBytes(4)
	if err != nil {
		return nil, nil, err
	}
	h.localIndex = binary.LittleEndian.Uint32(indexBytes)
	msg.SenderIndex = h.localIndex
	msg.ReceiverIndex = h.remoteIndex

	// Copy ephemeral public key
	copy(msg.Ephemeral[:], ephemeralPub[:])

	// Mix in our ephemeral
	h.hash = crypto.MixHash(h.hash, ephemeralPub[:])

	// DH: our ephemeral, their ephemeral
	ss, err := ephemeral.SharedSecret(h.remoteEphemeral)
	if err != nil {
		return nil, nil, err
	}

	newChainKey, _, err := crypto.MixKey(h.chainKey[:], ss)
	if err != nil {
		return nil, nil, err
	}
	copy(h.chainKey[:], newChainKey)

	// DH: our ephemeral, their static
	ss, err = ephemeral.SharedSecret(h.remoteStatic)
	if err != nil {
		return nil, nil, err
	}

	newChainKey, _, err = crypto.MixKey(h.chainKey[:], ss)
	if err != nil {
		return nil, nil, err
	}
	copy(h.chainKey[:], newChainKey)

	// Mix in pre-shared key
	newChainKey, tempKey, err := crypto.MixKey(h.chainKey[:], h.preSharedKey[:])
	if err != nil {
		return nil, nil, err
	}
	copy(h.chainKey[:], newChainKey)
	h.hash = crypto.MixHash(h.hash, tempKey)

	// Encrypt empty message
	_, key, err := crypto.MixKey(h.chainKey[:], nil)
	if err != nil {
		return nil, nil, err
	}

	aead, err := crypto.NewAEAD(key)
	if err != nil {
		return nil, nil, err
	}

	nonce := make([]byte, 12)
	encrypted := aead.Seal(nonce, nil, h.hash[:])
	copy(msg.EncryptedNothing[:], encrypted)

	h.hash = crypto.MixHash(h.hash, encrypted)

	// Compute MAC1
	mac1Key := crypto.Hash(append([]byte(LabelMAC1), h.remoteStatic[:]...))
	mac1Data := make([]byte, 60)
	mac1Data[0] = MessageTypeResponse
	binary.LittleEndian.PutUint32(mac1Data[4:], msg.SenderIndex)
	binary.LittleEndian.PutUint32(mac1Data[8:], msg.ReceiverIndex)
	copy(mac1Data[12:], msg.Ephemeral[:])
	copy(mac1Data[44:], msg.EncryptedNothing[:])

	mac1, err := crypto.HMAC(mac1Key[:], mac1Data)
	if err != nil {
		return nil, nil, err
	}
	copy(msg.MAC1[:], mac1[:16])

	// Derive session keys
	outputs, err := crypto.KDF(h.chainKey[:], nil, 2)
	if err != nil {
		return nil, nil, err
	}

	sendAEAD, err := crypto.NewAEAD(outputs[0])
	if err != nil {
		return nil, nil, err
	}
	receiveAEAD, err := crypto.NewAEAD(outputs[1])
	if err != nil {
		return nil, nil, err
	}

	session := &Session{
		localIndex:  h.localIndex,
		remoteIndex: h.remoteIndex,
		sendKey:     outputs[0],
		receiveKey:  outputs[1],
		sendAEAD:    sendAEAD,
		receiveAEAD: receiveAEAD,
		created:     time.Now(),
	}
	session.valid.Store(true)

	h.state = HandshakeResponseCreated
	h.lastResponse = time.Now()

	return msg, session, nil
}

// ConsumeResponse processes a received response message
func (h *Handshake) ConsumeResponse(msg *MessageResponse) (*Session, error) {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	if h.state != HandshakeInitiationCreated {
		return nil, errors.New("invalid handshake state")
	}

	if msg.ReceiverIndex != h.localIndex {
		return nil, errors.New("invalid receiver index")
	}

	// Store remote ephemeral
	copy(h.remoteEphemeral[:], msg.Ephemeral[:])
	h.remoteIndex = msg.SenderIndex

	// Mix in their ephemeral
	h.hash = crypto.MixHash(h.hash, msg.Ephemeral[:])

	// DH: our ephemeral, their ephemeral
	ss, err := h.localEphemeral.SharedSecret(h.remoteEphemeral)
	if err != nil {
		return nil, err
	}

	newChainKey, _, err := crypto.MixKey(h.chainKey[:], ss)
	if err != nil {
		return nil, err
	}
	copy(h.chainKey[:], newChainKey)

	// DH: our static, their ephemeral
	ss, err = h.localStatic.SharedSecret(h.remoteEphemeral)
	if err != nil {
		return nil, err
	}

	newChainKey, _, err = crypto.MixKey(h.chainKey[:], ss)
	if err != nil {
		return nil, err
	}
	copy(h.chainKey[:], newChainKey)

	// Mix in pre-shared key
	newChainKey, tempKey, err := crypto.MixKey(h.chainKey[:], h.preSharedKey[:])
	if err != nil {
		return nil, err
	}
	copy(h.chainKey[:], newChainKey)
	h.hash = crypto.MixHash(h.hash, tempKey)

	// Derive key and verify empty message
	_, key, err := crypto.MixKey(h.chainKey[:], nil)
	if err != nil {
		return nil, err
	}

	aead, err := crypto.NewAEAD(key)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, 12)
	_, err = aead.Open(nonce, msg.EncryptedNothing[:], h.hash[:])
	if err != nil {
		return nil, errors.New("failed to decrypt response")
	}

	h.hash = crypto.MixHash(h.hash, msg.EncryptedNothing[:])

	// Derive session keys
	outputs, err := crypto.KDF(h.chainKey[:], nil, 2)
	if err != nil {
		return nil, err
	}

	sendAEAD, err := crypto.NewAEAD(outputs[1])
	if err != nil {
		return nil, err
	}
	receiveAEAD, err := crypto.NewAEAD(outputs[0])
	if err != nil {
		return nil, err
	}

	session := &Session{
		localIndex:  h.localIndex,
		remoteIndex: h.remoteIndex,
		sendKey:     outputs[1], // Note: reversed from server
		receiveKey:  outputs[0],
		sendAEAD:    sendAEAD,
		receiveAEAD: receiveAEAD,
		created:     time.Now(),
	}
	session.valid.Store(true)

	h.state = HandshakeResponseConsumed

	return session, nil
}

// createTimestamp creates a TAI64N timestamp
func createTimestamp() []byte {
	now := time.Now()
	tai64n := make([]byte, 12)

	// TAI64 = Unix time + 2^62 + 10 (leap seconds approximation)
	tai64 := uint64(now.Unix()) + 0x400000000000000a
	binary.BigEndian.PutUint64(tai64n[0:8], tai64)
	binary.BigEndian.PutUint32(tai64n[8:12], uint32(now.Nanosecond()))

	return tai64n
}

// Encrypt encrypts data for transport — lock-free, safe for concurrent use
func (s *Session) Encrypt(plaintext []byte) ([]byte, error) {
	if !s.valid.Load() {
		return nil, errors.New("session not valid")
	}

	// Atomic increment — each goroutine gets unique counter
	counter := s.sendNonce.Add(1) - 1

	// Stack-allocated nonce
	var nonce [12]byte
	binary.LittleEndian.PutUint64(nonce[4:], counter)

	// Build output: header + ciphertext in one allocation
	out := make([]byte, MessageTransportHeaderSize, MessageTransportHeaderSize+len(plaintext)+s.sendAEAD.Overhead())
	out[0] = MessageTypeTransport
	binary.LittleEndian.PutUint32(out[4:], s.remoteIndex)
	binary.LittleEndian.PutUint64(out[8:], counter)

	out = s.sendAEAD.SealTo(out, nonce[:], plaintext, nil)
	return out, nil
}

// Decrypt decrypts data from transport — lock-free, safe for concurrent use
func (s *Session) Decrypt(data []byte) ([]byte, error) {
	if !s.valid.Load() {
		return nil, errors.New("session not valid")
	}

	if len(data) < MessageTransportHeaderSize+16 {
		return nil, errors.New("message too short")
	}

	counter := binary.LittleEndian.Uint64(data[8:16])

	// Replay protection (has its own mutex)
	if !s.replayFilter.ValidateCounter(counter) {
		return nil, errors.New("replay detected")
	}

	// Stack-allocated nonce
	var nonce [12]byte
	binary.LittleEndian.PutUint64(nonce[4:], counter)

	plaintext, err := s.receiveAEAD.Open(nonce[:], data[MessageTransportHeaderSize:], nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// ValidateCounter checks if a counter is valid (replay protection)
func (rf *ReplayFilter) ValidateCounter(counter uint64) bool {
	rf.mutex.Lock()
	defer rf.mutex.Unlock()

	if counter > rf.counter {
		// New counter, update bitmap
		diff := counter - rf.counter
		if diff > 512 {
			// Reset bitmap
			rf.bitmap = [512]bool{}
		} else {
			// Shift bitmap
			for i := uint64(0); i < diff && i < 512; i++ {
				rf.bitmap[(rf.counter+i)%512] = false
			}
		}
		rf.counter = counter
		rf.bitmap[counter%512] = true
		return true
	}

	// Check if within window
	if rf.counter-counter >= 512 {
		return false
	}

	// Check if already received
	if rf.bitmap[counter%512] {
		return false
	}

	rf.bitmap[counter%512] = true
	return true
}

// IsValid returns whether the session is valid
func (s *Session) IsValid() bool {
	return s.valid.Load()
}

// Invalidate marks the session as invalid
func (s *Session) Invalidate() {
	s.valid.Store(false)
}
