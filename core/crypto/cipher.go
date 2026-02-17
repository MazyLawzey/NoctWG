/* SPDX-License-Identifier: GPL-3.0
 *
 * Copyright (C) 2025 NoctWG. All Rights Reserved.
 */

package crypto

import (
	"crypto/cipher"
	"errors"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
)

// AEAD provides authenticated encryption with associated data
type AEAD struct {
	cipher cipher.AEAD
	key    []byte
}

// NewAEAD creates a new AEAD cipher with the given key
func NewAEAD(key []byte) (*AEAD, error) {
	if len(key) != chacha20poly1305.KeySize {
		return nil, errors.New("invalid key size for ChaCha20-Poly1305")
	}

	c, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}

	return &AEAD{
		cipher: c,
		key:    key,
	}, nil
}

// NewXAEAD creates a new XChaCha20-Poly1305 AEAD cipher
func NewXAEAD(key []byte) (*AEAD, error) {
	if len(key) != chacha20poly1305.KeySize {
		return nil, errors.New("invalid key size for XChaCha20-Poly1305")
	}

	c, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}

	return &AEAD{
		cipher: c,
		key:    key,
	}, nil
}

// Seal encrypts and authenticates plaintext with associated data
func (a *AEAD) Seal(nonce, plaintext, additionalData []byte) []byte {
	return a.cipher.Seal(nil, nonce, plaintext, additionalData)
}

// SealTo encrypts plaintext and appends the result to dst, avoiding extra allocations
func (a *AEAD) SealTo(dst, nonce, plaintext, additionalData []byte) []byte {
	return a.cipher.Seal(dst, nonce, plaintext, additionalData)
}

// Overhead returns the maximum difference between plaintext and ciphertext lengths
func (a *AEAD) Overhead() int {
	return a.cipher.Overhead()
}

// Open decrypts and verifies ciphertext with associated data
func (a *AEAD) Open(nonce, ciphertext, additionalData []byte) ([]byte, error) {
	return a.cipher.Open(nil, nonce, ciphertext, additionalData)
}

// NonceSize returns the nonce size for this AEAD
func (a *AEAD) NonceSize() int {
	return a.cipher.NonceSize()
}

// Hash computes BLAKE2s-256 hash
func Hash(data []byte) [blake2s.Size]byte {
	return blake2s.Sum256(data)
}

// Hash128 computes BLAKE2s-128 hash (using first 16 bytes of 256)
func Hash128(data []byte) [16]byte {
	full := blake2s.Sum256(data)
	var result [16]byte
	copy(result[:], full[:16])
	return result
}

// HMAC computes BLAKE2s-256 keyed hash (HMAC-like)
func HMAC(key, data []byte) ([blake2s.Size]byte, error) {
	h, err := blake2s.New256(key)
	if err != nil {
		return [blake2s.Size]byte{}, err
	}
	h.Write(data)
	var result [blake2s.Size]byte
	copy(result[:], h.Sum(nil))
	return result, nil
}

// KDF derives keys using BLAKE2s-based HKDF-like construction
func KDF(key, data []byte, outputs int) ([][]byte, error) {
	if outputs < 1 || outputs > 3 {
		return nil, errors.New("invalid number of outputs")
	}

	results := make([][]byte, outputs)

	// First extraction
	h, err := blake2s.New256(key)
	if err != nil {
		return nil, err
	}
	h.Write(data)
	t0 := h.Sum(nil)

	// First output
	h, err = blake2s.New256(t0)
	if err != nil {
		return nil, err
	}
	h.Write([]byte{0x01})
	results[0] = h.Sum(nil)

	if outputs >= 2 {
		h, err = blake2s.New256(t0)
		if err != nil {
			return nil, err
		}
		h.Write(results[0])
		h.Write([]byte{0x02})
		results[1] = h.Sum(nil)
	}

	if outputs >= 3 {
		h, err = blake2s.New256(t0)
		if err != nil {
			return nil, err
		}
		h.Write(results[1])
		h.Write([]byte{0x03})
		results[2] = h.Sum(nil)
	}

	return results, nil
}

// MixKey performs key mixing for the Noise protocol
func MixKey(chainKey []byte, input []byte) (newChainKey []byte, key []byte, err error) {
	outputs, err := KDF(chainKey, input, 2)
	if err != nil {
		return nil, nil, err
	}
	return outputs[0], outputs[1], nil
}

// MixHash mixes data into a hash
func MixHash(hash [blake2s.Size]byte, data []byte) [blake2s.Size]byte {
	h := blake2s.Sum256(append(hash[:], data...))
	return h
}
