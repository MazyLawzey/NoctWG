/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2025 NoctWG. All Rights Reserved.
 */

package main

import (
	"embed"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	noctwg "github.com/noctwg/noctwg"
	"github.com/noctwg/noctwg/config"
	"github.com/noctwg/noctwg/core/crypto"
	"github.com/noctwg/noctwg/core/protocol"
	"github.com/noctwg/noctwg/rpft"
	"github.com/noctwg/noctwg/tun"
)

//go:embed gui/*
var guiFS embed.FS

var (
	configPath   = flag.String("config", "", "Path to configuration file")
	genKey       = flag.Bool("genkey", false, "Generate a new private key")
	showVersion  = flag.Bool("version", false, "Show version information")
	enableGUI    = flag.Bool("gui", true, "Enable web GUI")
	guiPort      = flag.Int("gui-port", 8081, "GUI port")
	serverAddr   = flag.String("server", "", "Server address (host:port)")
	serverPubKey = flag.String("server-key", "", "Server public key")
	enableTUN    = flag.Bool("tun", false, "Enable TUN mode (full VPN)")
	tunAddress   = flag.String("tun-address", "10.0.0.2/24", "TUN interface address (CIDR)")
)

// Client represents the NoctWG client
type Client struct {
	config    *config.ClientConfig
	device    *protocol.Device
	peer      *protocol.Peer
	logger    *ClientLogger
	guiServer *http.Server
	tunDevice tun.Device
	connected bool
	stats     *ClientStats
}

// ClientStats holds client statistics
type ClientStats struct {
	Connected     bool      `json:"connected"`
	ConnectedAt   time.Time `json:"connected_at,omitempty"`
	BytesSent     uint64    `json:"bytes_sent"`
	BytesReceived uint64    `json:"bytes_received"`
	Latency       int64     `json:"latency_ms"`
	ServerAddr    string    `json:"server_addr"`
	PublicKey     string    `json:"public_key"`
	ServerKey     string    `json:"server_key"`
}

// ClientLogger implements the Logger interface
type ClientLogger struct {
	level string
}

func (l *ClientLogger) Verbosef(format string, args ...interface{}) {
	if l.level == "verbose" || l.level == "debug" {
		log.Printf("[VERBOSE] "+format, args...)
	}
}

func (l *ClientLogger) Errorf(format string, args ...interface{}) {
	log.Printf("[ERROR] "+format, args...)
}

func main() {
	flag.Parse()

	if *showVersion {
		fmt.Printf("NoctWG Client %s\n", noctwg.Version)
		fmt.Printf("Platform: %s/%s\n", runtime.GOOS, runtime.GOARCH)
		return
	}

	if *genKey {
		privateKey, err := crypto.GeneratePrivateKey()
		if err != nil {
			log.Fatalf("Failed to generate key: %v", err)
		}
		publicKey, err := privateKey.PublicKey()
		if err != nil {
			log.Fatalf("Failed to derive public key: %v", err)
		}
		fmt.Printf("Private Key: %s\n", privateKey.ToBase64())
		fmt.Printf("Public Key:  %s\n", publicKey.ToBase64())
		return
	}

	// Load or create configuration
	var cfg *config.ClientConfig
	var err error

	if *configPath != "" {
		cfg, err = config.LoadClientConfig(*configPath)
		if err != nil {
			log.Fatalf("Failed to load config: %v", err)
		}
	} else {
		cfg = config.DefaultClientConfig()
		cfg.GUIPort = uint16(*guiPort)
		cfg.GUIEnabled = *enableGUI

		if *serverAddr != "" {
			cfg.ServerAddress = *serverAddr
		}
		if *serverPubKey != "" {
			cfg.ServerPublicKey = *serverPubKey
		}
	}

	// Generate key if not set
	if cfg.PrivateKey == "" {
		privateKey, err := crypto.GeneratePrivateKey()
		if err != nil {
			log.Fatalf("Failed to generate key: %v", err)
		}
		cfg.PrivateKey = privateKey.ToBase64()

		publicKey, err := privateKey.PublicKey()
		if err != nil {
			log.Fatalf("Failed to derive public key: %v", err)
		}

		log.Printf("Generated new client keys")
		log.Printf("Public Key: %s", publicKey.ToBase64())

		if *configPath != "" {
			config.SaveClientConfig(*configPath, cfg)
		}
	}

	// Create client
	client, err := NewClient(cfg)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	// Start client
	if err := client.Start(); err != nil {
		log.Fatalf("Failed to start client: %v", err)
	}

	log.Printf("NoctWG Client %s started", noctwg.Version)
	if cfg.GUIEnabled {
		log.Printf("GUI available at http://%s:%d", cfg.GUIAddress, cfg.GUIPort)
	}

	// Auto-connect with TUN if enabled via CLI
	if *enableTUN && cfg.ServerAddress != "" && cfg.ServerPublicKey != "" {
		log.Printf("TUN mode enabled, connecting...")
		if err := client.ConnectWithTUN(*tunAddress); err != nil {
			log.Printf("Failed to connect with TUN: %v", err)
		}
	}

	// Wait for signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Println("Shutting down...")
	client.Stop()
}

// NewClient creates a new client instance
func NewClient(cfg *config.ClientConfig) (*Client, error) {
	privateKey, err := crypto.PrivateKeyFromBase64(cfg.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("invalid private key: %w", err)
	}

	logger := &ClientLogger{level: cfg.LogLevel}

	device, err := protocol.NewDevice(privateKey, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create device: %w", err)
	}

	client := &Client{
		config: cfg,
		device: device,
		logger: logger,
		stats:  &ClientStats{},
	}

	// Set up stats
	publicKey, _ := privateKey.PublicKey()
	client.stats.PublicKey = publicKey.ToBase64()
	client.stats.ServerKey = cfg.ServerPublicKey
	client.stats.ServerAddr = fmt.Sprintf("%s:%d", cfg.ServerAddress, cfg.ServerPort)

	return client, nil
}

// Start starts the client
func (c *Client) Start() error {
	// Start VPN device on random port
	if err := c.device.Listen(0); err != nil {
		return err
	}

	// Start GUI server if enabled
	if c.config.GUIEnabled {
		go c.startGUI()
	}

	return nil
}

// Connect connects to the VPN server
func (c *Client) Connect() error {
	if c.config.ServerAddress == "" || c.config.ServerPublicKey == "" {
		return fmt.Errorf("server address and public key required")
	}

	fmt.Printf("\n[CLIENT] Connecting to %s with server key: %s\n", c.config.ServerAddress, c.config.ServerPublicKey)

	serverPubKey, err := crypto.PublicKeyFromBase64(c.config.ServerPublicKey)
	if err != nil {
		return fmt.Errorf("invalid server public key: %w", err)
	}

	// Add server as peer
	peer, err := c.device.AddPeer(serverPubKey)
	if err != nil {
		return err
	}

	// Set endpoint
	endpoint := fmt.Sprintf("%s:%d", c.config.ServerAddress, c.config.ServerPort)
	if err := peer.SetEndpoint(endpoint); err != nil {
		return err
	}

	// Add allowed IPs
	for _, cidr := range c.config.AllowedIPs {
		peer.AddAllowedIP(cidr)
	}

	c.peer = peer

	// Initiate handshake
	fmt.Printf("[CLIENT] Initiating handshake...\n")
	if err := c.device.InitiateHandshake(peer); err != nil {
		return err
	}

	c.connected = true
	c.stats.Connected = true
	c.stats.ConnectedAt = time.Now()

	log.Printf("Connected to %s", endpoint)

	return nil
}

// ConnectWithTUN connects to VPN and creates TUN interface
func (c *Client) ConnectWithTUN(tunAddr string) error {
	// First establish connection
	if err := c.Connect(); err != nil {
		return err
	}

	// Parse TUN address
	ip, ipnet, err := net.ParseCIDR(tunAddr)
	if err != nil {
		return fmt.Errorf("invalid TUN address: %w", err)
	}

	// Create TUN device
	tunCfg := &tun.Config{
		Name:    "noctwg",
		MTU:     1420,
		Address: ip,
		Netmask: ipnet.Mask,
	}

	tunDev, err := tun.CreateTUN(tunCfg)
	if err != nil {
		return fmt.Errorf("failed to create TUN: %w", err)
	}

	c.tunDevice = tunDev

	// Configure TUN
	if err := tunDev.Configure(ip, ipnet.Mask); err != nil {
		log.Printf("Warning: failed to configure TUN address: %v", err)
	}

	// Bring interface up
	if err := tunDev.Up(); err != nil {
		log.Printf("Warning: failed to bring TUN up: %v", err)
	}

	// Set TUN on device
	c.device.SetTUN(tunDev, tunDev.Name())

	// Start TUN loop
	if err := c.device.StartTUNLoop(); err != nil {
		return fmt.Errorf("failed to start TUN loop: %w", err)
	}

	log.Printf("TUN interface %s configured with %s", tunDev.Name(), tunAddr)

	return nil
}

// Disconnect disconnects from the VPN server
func (c *Client) Disconnect() {
	if c.tunDevice != nil {
		c.tunDevice.Down()
		c.tunDevice.Close()
		c.tunDevice = nil
	}
	if c.peer != nil {
		c.device.RemovePeer(c.peer.PublicKey)
		c.peer = nil
	}
	c.connected = false
	c.stats.Connected = false
}

// Stop stops the client
func (c *Client) Stop() {
	c.Disconnect()
	if c.guiServer != nil {
		c.guiServer.Close()
	}
	c.device.Close()
}

// startGUI starts the web GUI server
func (c *Client) startGUI() {
	mux := http.NewServeMux()

	// API routes
	mux.HandleFunc("/api/status", c.handleStatus)
	mux.HandleFunc("/api/connect", c.handleConnect)
	mux.HandleFunc("/api/connect-tun", c.handleConnectTUN)
	mux.HandleFunc("/api/disconnect", c.handleDisconnect)
	mux.HandleFunc("/api/config", c.handleConfig)
	mux.HandleFunc("/api/rpft/tunnels", c.handleRPFTTunnels)
	mux.HandleFunc("/api/rpft/create", c.handleCreateTunnel)
	mux.HandleFunc("/api/rpft/start", c.handleStartTunnel)
	mux.HandleFunc("/api/rpft/stop", c.handleStopTunnel)
	mux.HandleFunc("/api/rpft/delete", c.handleDeleteTunnel)
	mux.HandleFunc("/api/genkey", c.handleGenKey)

	// Serve static files from embedded GUI
	guiContent, err := fs.Sub(guiFS, "gui")
	if err != nil {
		log.Printf("Failed to load GUI: %v", err)
		return
	}
	mux.Handle("/", http.FileServer(http.FS(guiContent)))

	addr := fmt.Sprintf("%s:%d", c.config.GUIAddress, c.config.GUIPort)
	c.guiServer = &http.Server{
		Addr:    addr,
		Handler: corsMiddleware(mux),
	}

	if err := c.guiServer.ListenAndServe(); err != http.ErrServerClosed {
		log.Printf("GUI server error: %v", err)
	}
}

// corsMiddleware adds CORS headers
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// API Handlers

func (c *Client) handleStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Update stats
	if c.peer != nil {
		c.stats.BytesSent = c.peer.BytesSent
		c.stats.BytesReceived = c.peer.BytesReceived
	}

	json.NewEncoder(w).Encode(c.stats)
}

func (c *Client) handleConnect(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Optionally accept new config
	var req struct {
		ServerAddress   string `json:"server_address"`
		ServerPort      uint16 `json:"server_port"`
		ServerPublicKey string `json:"server_public_key"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err == nil {
		if req.ServerAddress != "" {
			c.config.ServerAddress = req.ServerAddress
		}
		if req.ServerPort > 0 {
			c.config.ServerPort = req.ServerPort
		}
		if req.ServerPublicKey != "" {
			c.config.ServerPublicKey = req.ServerPublicKey
		}
	}

	if err := c.Connect(); err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "error",
			"error":  err.Error(),
		})
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"status": "connected"})
}

func (c *Client) handleConnectTUN(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		ServerAddress   string `json:"server_address"`
		ServerPort      uint16 `json:"server_port"`
		ServerPublicKey string `json:"server_public_key"`
		TUNAddress      string `json:"tun_address"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err == nil {
		if req.ServerAddress != "" {
			c.config.ServerAddress = req.ServerAddress
		}
		if req.ServerPort > 0 {
			c.config.ServerPort = req.ServerPort
		}
		if req.ServerPublicKey != "" {
			c.config.ServerPublicKey = req.ServerPublicKey
		}
	}

	tunAddr := req.TUNAddress
	if tunAddr == "" {
		tunAddr = "10.0.0.2/24"
	}

	if err := c.ConnectWithTUN(tunAddr); err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "error",
			"error":  err.Error(),
		})
		return
	}

	tunName := ""
	if c.tunDevice != nil {
		tunName = c.tunDevice.Name()
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":   "connected",
		"tun_name": tunName,
	})
}

func (c *Client) handleDisconnect(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	c.Disconnect()
	json.NewEncoder(w).Encode(map[string]string{"status": "disconnected"})
}

func (c *Client) handleConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		safeCfg := *c.config
		safeCfg.PrivateKey = "[hidden]"
		json.NewEncoder(w).Encode(safeCfg)
	case http.MethodPost:
		var newCfg config.ClientConfig
		if err := json.NewDecoder(r.Body).Decode(&newCfg); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		newCfg.PrivateKey = c.config.PrivateKey
		c.config = &newCfg
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (c *Client) handleRPFTTunnels(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	tunnels := c.device.GetRPFTHandler().GetManager().GetAllTunnels()

	result := make([]map[string]interface{}, len(tunnels))
	for i, t := range tunnels {
		result[i] = map[string]interface{}{
			"id":            t.ID,
			"name":          t.Name,
			"type":          tunnelTypeToString(t.Type),
			"protocol":      tunnelProtocolToString(t.Protocol),
			"local_host":    t.LocalHost,
			"local_port":    t.LocalPort,
			"remote_host":   t.RemoteHost,
			"remote_port":   t.RemotePort,
			"state":         tunnelStateToString(t.State),
			"bytes_sent":    t.BytesSent,
			"bytes_recv":    t.BytesRecv,
			"connections":   t.Connections,
			"last_activity": t.LastActivity,
		}
	}

	json.NewEncoder(w).Encode(result)
}

func (c *Client) handleCreateTunnel(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var cfg struct {
		Name       string `json:"name"`
		Type       string `json:"type"`
		Protocol   string `json:"protocol"`
		LocalHost  string `json:"local_host"`
		LocalPort  uint16 `json:"local_port"`
		RemoteHost string `json:"remote_host"`
		RemotePort uint16 `json:"remote_port"`
	}

	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	tunnelType := rpft.TunnelTypeLocalToRemote
	if cfg.Type == "remote_to_local" {
		tunnelType = rpft.TunnelTypeRemoteToLocal
	}

	tunnelProtocol := rpft.TunnelProtocolTCP
	if cfg.Protocol == "udp" {
		tunnelProtocol = rpft.TunnelProtocolUDP
	}

	tunnelCfg := rpft.TunnelConfig{
		Name:       cfg.Name,
		Type:       tunnelType,
		Protocol:   tunnelProtocol,
		LocalHost:  cfg.LocalHost,
		LocalPort:  cfg.LocalPort,
		RemoteHost: cfg.RemoteHost,
		RemotePort: cfg.RemotePort,
	}

	tunnel, err := c.device.GetRPFTHandler().GetManager().CreateTunnel(tunnelCfg)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":    "ok",
		"tunnel_id": tunnel.ID,
	})
}

func (c *Client) handleStartTunnel(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		TunnelID uint32 `json:"tunnel_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := c.device.GetRPFTHandler().StartTunnel(req.TunnelID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (c *Client) handleStopTunnel(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		TunnelID uint32 `json:"tunnel_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := c.device.GetRPFTHandler().StopTunnel(req.TunnelID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (c *Client) handleDeleteTunnel(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		TunnelID uint32 `json:"tunnel_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := c.device.GetRPFTHandler().GetManager().DeleteTunnel(req.TunnelID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (c *Client) handleGenKey(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	privateKey, err := crypto.GeneratePrivateKey()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	publicKey, err := privateKey.PublicKey()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{
		"private_key": privateKey.ToBase64(),
		"public_key":  publicKey.ToBase64(),
	})
}

// Helper functions
func tunnelTypeToString(t rpft.TunnelType) string {
	switch t {
	case rpft.TunnelTypeLocalToRemote:
		return "local_to_remote"
	case rpft.TunnelTypeRemoteToLocal:
		return "remote_to_local"
	default:
		return "unknown"
	}
}

func tunnelProtocolToString(p rpft.TunnelProtocol) string {
	switch p {
	case rpft.TunnelProtocolTCP:
		return "tcp"
	case rpft.TunnelProtocolUDP:
		return "udp"
	default:
		return "unknown"
	}
}

func tunnelStateToString(s rpft.TunnelState) string {
	switch s {
	case rpft.TunnelStateInactive:
		return "inactive"
	case rpft.TunnelStateActive:
		return "active"
	case rpft.TunnelStatePending:
		return "pending"
	case rpft.TunnelStateError:
		return "error"
	default:
		return "unknown"
	}
}
