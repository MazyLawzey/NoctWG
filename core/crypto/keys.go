/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2025 NoctWG. All Rights Reserved.
 */

package crypto

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"

	"golang.org/x/crypto/curve25519"
)

const (
	KeySize       = 32
	NonceSize     = 24
	TagSize       = 16
	TimestampSize = 12
)

// KeyPair represents a Curve25519 key pair
type KeyPair struct {
	PrivateKey [KeySize]byte
	PublicKey  [KeySize]byte
}

// PrivateKey represents a Curve25519 private key
type PrivateKey [KeySize]byte

// PublicKey represents a Curve25519 public key
type PublicKey [KeySize]byte

// GenerateKeyPair generates a new Curve25519 key pair
func GenerateKeyPair() (*KeyPair, error) {
	kp := &KeyPair{}

	// Generate random private key
	_, err := rand.Read(kp.PrivateKey[:])
	if err != nil {
		return nil, err
	}

	// Clamp the private key (for Curve25519)
	kp.PrivateKey[0] &= 248
	kp.PrivateKey[31] &= 127
	kp.PrivateKey[31] |= 64

	// Derive public key
	pubKey, err := curve25519.X25519(kp.PrivateKey[:], curve25519.Basepoint)
	if err != nil {
		return nil, err
	}
	copy(kp.PublicKey[:], pubKey)

	return kp, nil
}

// GeneratePrivateKey generates a new random private key
func GeneratePrivateKey() (PrivateKey, error) {
	var key PrivateKey
	_, err := rand.Read(key[:])
	if err != nil {
		return key, err
	}

	// Clamp for Curve25519
	key[0] &= 248
	key[31] &= 127
	key[31] |= 64

	return key, nil
}

// PublicKey derives the public key from a private key
func (sk *PrivateKey) PublicKey() (PublicKey, error) {
	var pk PublicKey
	pubKey, err := curve25519.X25519(sk[:], curve25519.Basepoint)
	if err != nil {
		return pk, err
	}
	copy(pk[:], pubKey)
	return pk, nil
}

// SharedSecret computes a shared secret using ECDH
func (sk *PrivateKey) SharedSecret(pk PublicKey) ([]byte, error) {
	return curve25519.X25519(sk[:], pk[:])
}

// ToBase64 encodes the private key to base64
func (sk *PrivateKey) ToBase64() string {
	return base64.StdEncoding.EncodeToString(sk[:])
}

// ToBase64 encodes the public key to base64
func (pk *PublicKey) ToBase64() string {
	return base64.StdEncoding.EncodeToString(pk[:])
}

// PrivateKeyFromBase64 decodes a private key from base64
func PrivateKeyFromBase64(s string) (PrivateKey, error) {
	var key PrivateKey
	// Clean up input string
	s = strings.TrimSpace(s)
	data, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return key, err
	}
	if len(data) != KeySize {
		return key, errors.New("invalid key size")
	}
	copy(key[:], data)
	return key, nil
}

// PublicKeyFromBase64 decodes a public key from base64
func PublicKeyFromBase64(s string) (PublicKey, error) {
	var key PublicKey
	// Clean up input string
	s = strings.TrimSpace(s)
	data, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return key, err
	}
	if len(data) != KeySize {
		return key, errors.New("invalid key size")
	}
	copy(key[:], data)
	return key, nil
}

// IsZero checks if the key is all zeros
func (pk *PublicKey) IsZero() bool {
	var zero PublicKey
	return *pk == zero
}

// IsZero checks if the key is all zeros
func (sk *PrivateKey) IsZero() bool {
	var zero PrivateKey
	return *sk == zero
}

// GenerateNonce generates a random nonce
func GenerateNonce() ([NonceSize]byte, error) {
	var nonce [NonceSize]byte
	_, err := rand.Read(nonce[:])
	return nonce, err
}

// GenerateRandomBytes generates n random bytes
func GenerateRandomBytes(n int) ([]byte, error) {
	bytes := make([]byte, n)
	_, err := rand.Read(bytes)
	return bytes, err
}
