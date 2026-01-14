/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2025 NoctWG. All Rights Reserved.
 */

// Package tun provides cross-platform TUN device support
package tun

import (
	"errors"
	"io"
	"net"
)

const (
	// DefaultMTU is the default MTU for the TUN device
	DefaultMTU = 1420
)

var (
	ErrTUNNotSupported = errors.New("TUN not supported on this platform")
	ErrTUNClosed       = errors.New("TUN device closed")
	ErrInvalidPacket   = errors.New("invalid packet")
)

// Device represents a TUN device
type Device interface {
	io.ReadWriteCloser

	// Name returns the interface name
	Name() string

	// MTU returns the MTU of the device
	MTU() int

	// SetMTU sets the MTU of the device
	SetMTU(mtu int) error

	// Configure sets the IP address and netmask
	Configure(address net.IP, netmask net.IPMask) error

	// AddRoute adds a route through this interface
	AddRoute(destination *net.IPNet) error

	// RemoveRoute removes a route
	RemoveRoute(destination *net.IPNet) error

	// Up brings the interface up
	Up() error

	// Down brings the interface down
	Down() error
}

// Config contains TUN device configuration
type Config struct {
	Name    string     // Interface name (optional, auto-generated if empty)
	MTU     int        // MTU (default: 1420)
	Address net.IP     // IP address for the interface
	Netmask net.IPMask // Network mask
	Gateway net.IP     // Gateway IP (optional)
	DNS     []net.IP   // DNS servers (optional)
}

// DefaultConfig returns a default configuration
func DefaultConfig() *Config {
	return &Config{
		MTU:     DefaultMTU,
		Address: net.ParseIP("10.0.0.2"),
		Netmask: net.CIDRMask(24, 32),
	}
}

// CreateTUN creates a new TUN device with the given configuration
// Platform-specific implementation in tun_*.go files
func CreateTUN(config *Config) (Device, error) {
	if config == nil {
		config = DefaultConfig()
	}
	if config.MTU == 0 {
		config.MTU = DefaultMTU
	}
	return createPlatformTUN(config)
}

// ParseCIDR parses a CIDR string and returns IP and mask
func ParseCIDR(cidr string) (net.IP, net.IPMask, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, nil, err
	}
	return ip, ipnet.Mask, nil
}
