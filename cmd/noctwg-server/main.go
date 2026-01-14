/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2025 NoctWG. All Rights Reserved.
 */

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	noctwg "github.com/noctwg/noctwg"
	"github.com/noctwg/noctwg/config"
	"github.com/noctwg/noctwg/core/crypto"
	"github.com/noctwg/noctwg/core/protocol"
	"github.com/noctwg/noctwg/rpft"
)

var (
	configPath     = flag.String("config", "", "Path to configuration file")
	genKey         = flag.Bool("genkey", false, "Generate a new private key")
	showVersion    = flag.Bool("version", false, "Show version information")
	listenPort     = flag.Int("port", 51820, "Listen port")
	apiPort        = flag.Int("api-port", 8080, "API port")
	enableAPI      = flag.Bool("api", true, "Enable management API")
	privateKeyFlag = flag.String("private-key", "", "Server private key (base64)")
)

// Server represents the NoctWG server
type Server struct {
	config    *config.ServerConfig
	device    *protocol.Device
	logger    *ServerLogger
	apiServer *http.Server
}

// ServerLogger implements the Logger interface
type ServerLogger struct {
	level string
}

func (l *ServerLogger) Verbosef(format string, args ...interface{}) {
	if l.level == "verbose" || l.level == "debug" {
		log.Printf("[VERBOSE] "+format, args...)
	}
}

func (l *ServerLogger) Errorf(format string, args ...interface{}) {
	log.Printf("[ERROR] "+format, args...)
}

func main() {
	flag.Parse()

	if *showVersion {
		fmt.Printf("NoctWG Server %s\n", noctwg.Version)
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
	var cfg *config.ServerConfig
	var err error

	if *configPath != "" {
		cfg, err = config.LoadServerConfig(*configPath)
		if err != nil {
			log.Fatalf("Failed to load config: %v", err)
		}
	} else {
		cfg = config.DefaultServerConfig()
		cfg.ListenPort = uint16(*listenPort)
		cfg.APIPort = uint16(*apiPort)
		cfg.APIEnabled = *enableAPI
	}

	// Use private key from flag if provided
	if *privateKeyFlag != "" {
		cfg.PrivateKey = *privateKeyFlag
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

		log.Printf("Generated new server keys")
		log.Printf("Public Key: %s", publicKey.ToBase64())

		if *configPath != "" {
			config.SaveServerConfig(*configPath, cfg)
		}
	}

	// Create server
	server, err := NewServer(cfg)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}

	// Start server
	if err := server.Start(); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}

	log.Printf("NoctWG Server %s started on port %d", noctwg.Version, cfg.ListenPort)
	log.Printf("Server Public Key: %s", server.device.GetPublicKey().ToBase64())
	if cfg.APIEnabled {
		log.Printf("API available at http://%s:%d", cfg.APIAddress, cfg.APIPort)
	}

	// Wait for signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Println("Shutting down...")
	server.Stop()
}

// NewServer creates a new server instance
func NewServer(cfg *config.ServerConfig) (*Server, error) {
	privateKey, err := crypto.PrivateKeyFromBase64(cfg.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("invalid private key: %w", err)
	}

	logger := &ServerLogger{level: cfg.LogLevel}

	device, err := protocol.NewDevice(privateKey, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create device: %w", err)
	}

	server := &Server{
		config: cfg,
		device: device,
		logger: logger,
	}

	// Add configured peers
	for _, peerCfg := range cfg.Peers {
		if err := server.addPeer(peerCfg); err != nil {
			log.Printf("Warning: failed to add peer %s: %v", peerCfg.Name, err)
		}
	}

	return server, nil
}

// addPeer adds a peer to the server
func (s *Server) addPeer(cfg config.PeerConfig) error {
	publicKey, err := crypto.PublicKeyFromBase64(cfg.PublicKey)
	if err != nil {
		return err
	}

	peer, err := s.device.AddPeer(publicKey)
	if err != nil {
		return err
	}

	for _, cidr := range cfg.AllowedIPs {
		if err := peer.AddAllowedIP(cidr); err != nil {
			log.Printf("Warning: invalid allowed IP %s: %v", cidr, err)
		}
	}

	return nil
}

// Start starts the server
func (s *Server) Start() error {
	// Start VPN device
	if err := s.device.Listen(s.config.ListenPort); err != nil {
		return err
	}

	// Start API server if enabled
	if s.config.APIEnabled {
		go s.startAPI()
	}

	return nil
}

// Stop stops the server
func (s *Server) Stop() {
	if s.apiServer != nil {
		s.apiServer.Close()
	}
	s.device.Close()
}

// startAPI starts the management API
func (s *Server) startAPI() {
	mux := http.NewServeMux()

	// API routes
	mux.HandleFunc("/api/status", s.handleStatus)
	mux.HandleFunc("/api/peers", s.handlePeers)
	mux.HandleFunc("/api/peers/add", s.handleAddPeer)
	mux.HandleFunc("/api/peers/remove", s.handleRemovePeer)
	mux.HandleFunc("/api/rpft/tunnels", s.handleRPFTTunnels)
	mux.HandleFunc("/api/rpft/create", s.handleCreateTunnel)
	mux.HandleFunc("/api/rpft/start", s.handleStartTunnel)
	mux.HandleFunc("/api/rpft/stop", s.handleStopTunnel)
	mux.HandleFunc("/api/config", s.handleConfig)

	addr := fmt.Sprintf("%s:%d", s.config.APIAddress, s.config.APIPort)
	s.apiServer = &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	if err := s.apiServer.ListenAndServe(); err != http.ErrServerClosed {
		log.Printf("API server error: %v", err)
	}
}

// API Handlers

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	status := map[string]interface{}{
		"version":    noctwg.Version,
		"port":       s.config.ListenPort,
		"public_key": s.device.GetPublicKey().ToBase64(),
		"peers":      len(s.config.Peers),
		"uptime":     "running",
	}
	json.NewEncoder(w).Encode(status)
}

func (s *Server) handlePeers(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(s.config.Peers)
}

func (s *Server) handleAddPeer(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var peerCfg config.PeerConfig
	if err := json.NewDecoder(r.Body).Decode(&peerCfg); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := s.addPeer(peerCfg); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	s.config.Peers = append(s.config.Peers, peerCfg)
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (s *Server) handleRemovePeer(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		PublicKey string `json:"public_key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	publicKey, err := crypto.PublicKeyFromBase64(req.PublicKey)
	if err != nil {
		http.Error(w, "Invalid public key", http.StatusBadRequest)
		return
	}

	s.device.RemovePeer(publicKey)

	// Remove from config
	for i, p := range s.config.Peers {
		if p.PublicKey == req.PublicKey {
			s.config.Peers = append(s.config.Peers[:i], s.config.Peers[i+1:]...)
			break
		}
	}

	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (s *Server) handleRPFTTunnels(w http.ResponseWriter, r *http.Request) {
	tunnels := s.device.GetRPFTHandler().GetManager().GetAllTunnels()

	result := make([]map[string]interface{}, len(tunnels))
	for i, t := range tunnels {
		result[i] = map[string]interface{}{
			"id":          t.ID,
			"name":        t.Name,
			"type":        t.Type,
			"protocol":    t.Protocol,
			"local_port":  t.LocalPort,
			"remote_port": t.RemotePort,
			"state":       t.State,
			"bytes_sent":  t.BytesSent,
			"bytes_recv":  t.BytesRecv,
			"connections": t.Connections,
		}
	}

	json.NewEncoder(w).Encode(result)
}

func (s *Server) handleCreateTunnel(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var cfg struct {
		Name       string `json:"name"`
		Type       string `json:"type"`
		Protocol   string `json:"protocol"`
		LocalPort  uint16 `json:"local_port"`
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
		LocalPort:  cfg.LocalPort,
		RemotePort: cfg.RemotePort,
	}

	tunnel, err := s.device.GetRPFTHandler().GetManager().CreateTunnel(tunnelCfg)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":    "ok",
		"tunnel_id": tunnel.ID,
	})
}

func (s *Server) handleStartTunnel(w http.ResponseWriter, r *http.Request) {
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

	if err := s.device.GetRPFTHandler().StartTunnel(req.TunnelID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (s *Server) handleStopTunnel(w http.ResponseWriter, r *http.Request) {
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

	if err := s.device.GetRPFTHandler().StopTunnel(req.TunnelID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		// Return config (with private key masked)
		safeCfg := *s.config
		safeCfg.PrivateKey = "[hidden]"
		json.NewEncoder(w).Encode(safeCfg)
	case http.MethodPost:
		// Update config
		var newCfg config.ServerConfig
		if err := json.NewDecoder(r.Body).Decode(&newCfg); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		// Preserve private key
		newCfg.PrivateKey = s.config.PrivateKey
		s.config = &newCfg
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}
