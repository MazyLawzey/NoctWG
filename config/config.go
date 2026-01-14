/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2025 NoctWG. All Rights Reserved.
 */

package config

import (
	"encoding/json"
	"os"
)

// ServerConfig represents the server configuration
type ServerConfig struct {
	// Network settings
	ListenAddress string `json:"listen_address"`
	ListenPort    uint16 `json:"listen_port"`

	// Keys
	PrivateKey string `json:"private_key"`

	// Peers configuration
	Peers []PeerConfig `json:"peers"`

	// RPFT settings
	RPFT RPFTConfig `json:"rpft"`

	// Logging
	LogLevel string `json:"log_level"`
	LogFile  string `json:"log_file"`

	// API settings
	APIEnabled bool   `json:"api_enabled"`
	APIAddress string `json:"api_address"`
	APIPort    uint16 `json:"api_port"`
}

// ClientConfig represents the client configuration
type ClientConfig struct {
	// Server settings
	ServerAddress   string `json:"server_address"`
	ServerPort      uint16 `json:"server_port"`
	ServerPublicKey string `json:"server_public_key"`

	// Keys
	PrivateKey string `json:"private_key"`

	// Network settings
	TunnelAddress string   `json:"tunnel_address"`
	DNS           []string `json:"dns"`
	AllowedIPs    []string `json:"allowed_ips"`

	// Keep-alive
	PersistentKeepalive int `json:"persistent_keepalive"`

	// RPFT settings
	RPFT RPFTConfig `json:"rpft"`

	// GUI settings
	GUIEnabled bool   `json:"gui_enabled"`
	GUIAddress string `json:"gui_address"`
	GUIPort    uint16 `json:"gui_port"`

	// Logging
	LogLevel string `json:"log_level"`
	LogFile  string `json:"log_file"`
}

// PeerConfig represents a peer configuration
type PeerConfig struct {
	Name                string   `json:"name"`
	PublicKey           string   `json:"public_key"`
	PreSharedKey        string   `json:"preshared_key,omitempty"`
	AllowedIPs          []string `json:"allowed_ips"`
	Endpoint            string   `json:"endpoint,omitempty"`
	PersistentKeepalive int      `json:"persistent_keepalive,omitempty"`
}

// RPFTConfig represents RPFT configuration
type RPFTConfig struct {
	Enabled           bool           `json:"enabled"`
	MaxTunnelsPerPeer int            `json:"max_tunnels_per_peer"`
	Tunnels           []TunnelConfig `json:"tunnels"`
}

// TunnelConfig represents a tunnel configuration
type TunnelConfig struct {
	Name       string `json:"name"`
	Type       string `json:"type"`     // "local_to_remote" or "remote_to_local"
	Protocol   string `json:"protocol"` // "tcp" or "udp"
	LocalHost  string `json:"local_host"`
	LocalPort  uint16 `json:"local_port"`
	RemoteHost string `json:"remote_host"`
	RemotePort uint16 `json:"remote_port"`
}

// LoadServerConfig loads server configuration from a file
func LoadServerConfig(path string) (*ServerConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	config := &ServerConfig{}
	if err := json.Unmarshal(data, config); err != nil {
		return nil, err
	}

	// Set defaults
	if config.ListenAddress == "" {
		config.ListenAddress = "0.0.0.0"
	}
	if config.ListenPort == 0 {
		config.ListenPort = 51820
	}
	if config.LogLevel == "" {
		config.LogLevel = "info"
	}
	if config.APIAddress == "" {
		config.APIAddress = "127.0.0.1"
	}
	if config.APIPort == 0 {
		config.APIPort = 8080
	}

	return config, nil
}

// LoadClientConfig loads client configuration from a file
func LoadClientConfig(path string) (*ClientConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	config := &ClientConfig{}
	if err := json.Unmarshal(data, config); err != nil {
		return nil, err
	}

	// Set defaults
	if config.ServerPort == 0 {
		config.ServerPort = 51820
	}
	if config.LogLevel == "" {
		config.LogLevel = "info"
	}
	if config.GUIAddress == "" {
		config.GUIAddress = "127.0.0.1"
	}
	if config.GUIPort == 0 {
		config.GUIPort = 8081
	}
	if len(config.DNS) == 0 {
		config.DNS = []string{"1.1.1.1", "8.8.8.8"}
	}

	return config, nil
}

// SaveServerConfig saves server configuration to a file
func SaveServerConfig(path string, config *ServerConfig) error {
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

// SaveClientConfig saves client configuration to a file
func SaveClientConfig(path string, config *ClientConfig) error {
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

// DefaultServerConfig returns a default server configuration
func DefaultServerConfig() *ServerConfig {
	return &ServerConfig{
		ListenAddress: "0.0.0.0",
		ListenPort:    51820,
		Peers:         []PeerConfig{},
		RPFT: RPFTConfig{
			Enabled:           true,
			MaxTunnelsPerPeer: 10,
			Tunnels:           []TunnelConfig{},
		},
		LogLevel:   "info",
		APIEnabled: true,
		APIAddress: "127.0.0.1",
		APIPort:    8080,
	}
}

// DefaultClientConfig returns a default client configuration
func DefaultClientConfig() *ClientConfig {
	return &ClientConfig{
		ServerPort:          51820,
		AllowedIPs:          []string{"0.0.0.0/0", "::/0"},
		DNS:                 []string{"1.1.1.1", "8.8.8.8"},
		PersistentKeepalive: 25,
		RPFT: RPFTConfig{
			Enabled: true,
			Tunnels: []TunnelConfig{},
		},
		LogLevel:   "info",
		GUIEnabled: true,
		GUIAddress: "127.0.0.1",
		GUIPort:    8081,
	}
}
