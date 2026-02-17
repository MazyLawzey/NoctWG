
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
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	noctwg "github.com/MazyLawzey/noctwg"
	"github.com/MazyLawzey/noctwg/config"
	"github.com/MazyLawzey/noctwg/core/crypto"
	"github.com/MazyLawzey/noctwg/core/protocol"
	"github.com/MazyLawzey/noctwg/rpft"
	"github.com/MazyLawzey/noctwg/tun"
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

	// On Windows, ensure firewall allows inbound UDP for this binary
	if runtime.GOOS == "windows" {
		ensureWindowsFirewall()
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

	// Already connected — skip
	if c.connected && c.peer != nil {
		session := c.peer.GetSession()
		if session != nil {
			fmt.Printf("[CLIENT] Already connected, skipping reconnect\n")
			return nil
		}
	}

	// Clean up previous connection if any
	if c.peer != nil {
		c.device.RemovePeer(c.peer.PublicKey)
		c.peer = nil
		c.connected = false
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

	// Initiate handshake with retries (3 attempts, 5s each)
	fmt.Printf("[CLIENT] Initiating handshake...\n")
	session, err := c.device.InitiateHandshakeWithRetry(peer, 3, 5*time.Second)
	if err != nil {
		// Clean up
		c.device.RemovePeer(peer.PublicKey)
		c.peer = nil
		return fmt.Errorf("handshake failed: %w", err)
	}

	_ = session
	c.connected = true
	c.stats.Connected = true
	c.stats.ConnectedAt = time.Now()

	log.Printf("Connected to %s (session established)", endpoint)

	return nil
}

// ConnectWithTUN connects to VPN and creates TUN interface
func (c *Client) ConnectWithTUN(tunAddr string) error {
	fmt.Printf("\n[CLIENT] ConnectWithTUN: Starting TUN connection with address %s\n", tunAddr)

	// First establish connection
	fmt.Printf("[CLIENT] ConnectWithTUN: Establishing base connection...\n")
	if err := c.Connect(); err != nil {
		fmt.Printf("[CLIENT] ConnectWithTUN: Base connection failed: %v\n", err)
		return err
	}
	fmt.Printf("[CLIENT] ConnectWithTUN: Base connection established\n")

	// Parse TUN address
	fmt.Printf("[CLIENT] ConnectWithTUN: Parsing TUN address %s...\n", tunAddr)
	ip, ipnet, err := net.ParseCIDR(tunAddr)
	if err != nil {
		fmt.Printf("[CLIENT] ConnectWithTUN: Invalid address: %v\n", err)
		return fmt.Errorf("invalid TUN address: %w", err)
	}
	fmt.Printf("[CLIENT] ConnectWithTUN: Parsed address=%s netmask=%s\n", ip.String(), ipnet.Mask.String())

	// Create TUN device
	fmt.Printf("[CLIENT] ConnectWithTUN: Creating TUN device...\n")
	tunCfg := &tun.Config{
		Name:    "noctwg",
		MTU:     1420,
		Address: ip,
		Netmask: ipnet.Mask,
	}

	tunDev, err := tun.CreateTUN(tunCfg)
	if err != nil {
		fmt.Printf("[CLIENT] ConnectWithTUN: Failed to create TUN: %v\n", err)
		return fmt.Errorf("failed to create TUN: %w", err)
	}
	fmt.Printf("[CLIENT] ConnectWithTUN: TUN device created successfully: %s\n", tunDev.Name())

	c.tunDevice = tunDev

	// Configure TUN
	fmt.Printf("[CLIENT] ConnectWithTUN: Configuring TUN...\n")
	if err := tunDev.Configure(ip, ipnet.Mask); err != nil {
		fmt.Printf("[CLIENT] ConnectWithTUN: Warning - failed to configure TUN: %v\n", err)
		log.Printf("Warning: failed to configure TUN address: %v", err)
	} else {
		fmt.Printf("[CLIENT] ConnectWithTUN: TUN configured successfully\n")
	}

	// Bring interface up
	fmt.Printf("[CLIENT] ConnectWithTUN: Bringing interface up...\n")
	if err := tunDev.Up(); err != nil {
		fmt.Printf("[CLIENT] ConnectWithTUN: Warning - failed to bring TUN up: %v\n", err)
		log.Printf("Warning: failed to bring TUN up: %v", err)
	} else {
		fmt.Printf("[CLIENT] ConnectWithTUN: TUN brought up successfully\n")
	}

	// Disable IPv6 on VPN adapter (prevents IPv6 traffic going through tunnel)
	fmt.Printf("[CLIENT] ConnectWithTUN: Disabling IPv6 on VPN adapter...\n")
	disableIPv6(tunDev.Name())

	// Wait for Windows to fully initialize the interface before adding routes
	fmt.Printf("[CLIENT] ConnectWithTUN: Waiting for interface to stabilize...\n")
	time.Sleep(2 * time.Second)

	// Add route exclusion for the real server IP FIRST (so VPN traffic itself doesn't loop)
	serverIP := c.config.ServerAddress
	fmt.Printf("[CLIENT] ConnectWithTUN: Adding route exclusion for server %s...\n", serverIP)
	addServerRouteExclusion(serverIP)

	// Now add default route through VPN (AFTER interface is up + IPv6 disabled + server route excluded)
	fmt.Printf("[CLIENT] ConnectWithTUN: Adding default IPv4 route through VPN...\n")
	if err := addDefaultVPNRoute(tunDev.Name(), ip); err != nil {
		fmt.Printf("[CLIENT] ConnectWithTUN: WARNING - default route failed: %v\n", err)
	} else {
		fmt.Printf("[CLIENT] ConnectWithTUN: Default route added successfully\n")
	}

	// Set DNS to public resolvers through VPN
	fmt.Printf("[CLIENT] ConnectWithTUN: Configuring DNS...\n")
	setVPNDns(tunDev.Name())

	// Verify routing
	verifyRoutes()

	// Set TUN on device
	fmt.Printf("[CLIENT] ConnectWithTUN: Setting TUN on device...\n")
	c.device.SetTUN(tunDev, tunDev.Name())

	// Start TUN loop
	fmt.Printf("[CLIENT] ConnectWithTUN: Starting TUN loop...\n")
	if err := c.device.StartTUNLoop(); err != nil {
		fmt.Printf("[CLIENT] ConnectWithTUN: Failed to start TUN loop: %v\n", err)
		return fmt.Errorf("failed to start TUN loop: %w", err)
	}

	fmt.Printf("[CLIENT] ConnectWithTUN: SUCCESS! TUN %s configured with %s\n", tunDev.Name(), tunAddr)
	log.Printf("TUN interface %s configured with %s", tunDev.Name(), tunAddr)

	return nil
}

// disableIPv6 disables IPv6 on the VPN adapter to prevent leaks
func disableIPv6(ifaceName string) {
	if runtime.GOOS != "windows" {
		return
	}
	// Method 1: PowerShell Disable-NetAdapterBinding (most reliable)
	psCmd := fmt.Sprintf("Disable-NetAdapterBinding -Name '%s' -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue", ifaceName)
	cmd := exec.Command("powershell", "-Command", psCmd)
	out, err := cmd.CombinedOutput()
	fmt.Printf("[CLIENT] Disable IPv6 (PowerShell): %s (err=%v)\n", strings.TrimSpace(string(out)), err)

	// Method 2: netsh fallback
	cmd = exec.Command("netsh", "interface", "ipv6", "set", "interface",
		ifaceName, "disabled")
	out, err = cmd.CombinedOutput()
	fmt.Printf("[CLIENT] Disable IPv6 (netsh): %s (err=%v)\n", strings.TrimSpace(string(out)), err)
}

// addDefaultVPNRoute adds 0.0.0.0/0 via VPN gateway using route command
func addDefaultVPNRoute(ifaceName string, clientIP net.IP) error {
	if runtime.GOOS != "windows" {
		return nil
	}

	gatewayIP := net.IP(make([]byte, len(clientIP)))
	copy(gatewayIP, clientIP)
	gatewayIP[len(gatewayIP)-1] = 1 // 10.0.0.1

	// Find interface index
	var ifIdx int
	ifaces, _ := net.Interfaces()
	for _, iface := range ifaces {
		if iface.Name == ifaceName {
			ifIdx = iface.Index
			break
		}
	}

	fmt.Printf("[CLIENT] Adding default route 0.0.0.0/0 via %s (iface=%s idx=%d)\n", gatewayIP, ifaceName, ifIdx)

	// route add 0.0.0.0 mask 0.0.0.0 <gateway> metric 5 if <idx>
	args := []string{"add", "0.0.0.0", "mask", "0.0.0.0", gatewayIP.String(), "metric", "5"}
	if ifIdx > 0 {
		args = append(args, "if", fmt.Sprintf("%d", ifIdx))
	}
	cmd := exec.Command("route", args...)
	out, err := cmd.CombinedOutput()
	fmt.Printf("[CLIENT] route add: %s (err=%v)\n", strings.TrimSpace(string(out)), err)
	return err
}

// verifyRoutes prints current routing table for debugging
func verifyRoutes() {
	if runtime.GOOS != "windows" {
		return
	}
	cmd := exec.Command("route", "print", "0.0.0.0")
	out, _ := cmd.Output()
	lines := strings.Split(string(out), "\n")
	fmt.Printf("[CLIENT] === Routing table (0.0.0.0) ===\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" && (strings.Contains(trimmed, "0.0.0.0") || strings.Contains(trimmed, "Gateway") || strings.Contains(trimmed, "Metric")) {
			fmt.Printf("[CLIENT]   %s\n", trimmed)
		}
	}
	fmt.Printf("[CLIENT] === End routing table ===\n")
}

// setVPNDns sets DNS servers on the VPN adapter so all DNS queries go through the tunnel
func setVPNDns(ifaceName string) {
	if runtime.GOOS != "windows" {
		return
	}

	// Set primary DNS
	cmd := exec.Command("netsh", "interface", "ipv4", "set", "dnsservers",
		ifaceName, "static", "1.1.1.1", "primary")
	out, err := cmd.CombinedOutput()
	fmt.Printf("[CLIENT] DNS primary (1.1.1.1): %s (err=%v)\n", strings.TrimSpace(string(out)), err)

	// Add secondary DNS
	cmd = exec.Command("netsh", "interface", "ipv4", "add", "dnsservers",
		ifaceName, "8.8.8.8", "index=2")
	out, err = cmd.CombinedOutput()
	fmt.Printf("[CLIENT] DNS secondary (8.8.8.8): %s (err=%v)\n", strings.TrimSpace(string(out)), err)

	// Set VPN adapter DNS to higher priority (lower metric = higher priority)
	psCmd := fmt.Sprintf("Set-DnsClientServerAddress -InterfaceAlias '%s' -ServerAddresses ('1.1.1.1','8.8.8.8') -ErrorAction SilentlyContinue", ifaceName)
	cmd = exec.Command("powershell", "-Command", psCmd)
	out, err = cmd.CombinedOutput()
	fmt.Printf("[CLIENT] DNS PowerShell: %s (err=%v)\n", strings.TrimSpace(string(out)), err)

	// Flush DNS cache so old entries don't persist
	cmd = exec.Command("ipconfig", "/flushdns")
	out, err = cmd.CombinedOutput()
	fmt.Printf("[CLIENT] DNS flush: %s (err=%v)\n", strings.TrimSpace(string(out)), err)
}

// addServerRouteExclusion adds a specific route for the VPN server IP
// through the default gateway, so VPN packets themselves don't loop through the tunnel
func addServerRouteExclusion(serverIP string) {
	if runtime.GOOS != "windows" {
		return
	}

	// Find the current default gateway
	gateway := findDefaultGateway()
	if gateway == "" {
		fmt.Printf("[CLIENT] WARNING: Could not detect default gateway\n")
		return
	}
	fmt.Printf("[CLIENT] Default gateway: %s\n", gateway)

	// Add route: serverIP -> real gateway (so VPN UDP packets go direct)
	cmd := exec.Command("route", "add", serverIP, "mask", "255.255.255.255", gateway, "metric", "1")
	out, err := cmd.CombinedOutput()
	fmt.Printf("[CLIENT] Route add %s via %s: %s (err=%v)\n", serverIP, gateway, string(out), err)
}

// findDefaultGateway returns the default gateway IP on Windows
func findDefaultGateway() string {
	cmd := exec.Command("cmd", "/c", "route", "print", "0.0.0.0")
	out, err := cmd.Output()
	if err != nil {
		return ""
	}

	// Parse route table output to find default gateway
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 5 && fields[0] == "0.0.0.0" && fields[1] == "0.0.0.0" {
			return fields[2] // gateway
		}
	}
	return ""
}

// removeServerRouteExclusion removes the server route exclusion on disconnect
func removeServerRouteExclusion(serverIP string) {
	if runtime.GOOS != "windows" || serverIP == "" {
		return
	}
	cmd := exec.Command("route", "delete", serverIP)
	cmd.Run()
}

// Disconnect disconnects from the VPN server
func (c *Client) Disconnect() {
	// Remove server route exclusion
	if c.config != nil && c.config.ServerAddress != "" {
		removeServerRouteExclusion(c.config.ServerAddress)
	}
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

// ensureWindowsFirewall adds a Windows Firewall rule to allow inbound UDP
// for the current executable. Silently ignores errors (non-admin, etc.)
func ensureWindowsFirewall() {
	exePath, err := os.Executable()
	if err != nil {
		return
	}

	ruleName := "NoctWG Client (UDP Inbound)"

	// Check if rule already exists
	check := exec.Command("netsh", "advfirewall", "firewall", "show", "rule", "name="+ruleName)
	if err := check.Run(); err == nil {
		// Rule already exists
		log.Printf("Firewall rule '%s' already exists", ruleName)
		return
	}

	// Add the rule
	log.Printf("Adding Windows Firewall rule for inbound UDP...")
	cmd := exec.Command("netsh", "advfirewall", "firewall", "add", "rule",
		"name="+ruleName,
		"dir=in",
		"action=allow",
		"protocol=UDP",
		"program="+exePath,
		"enable=yes",
		"profile=any",
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("Warning: Could not add firewall rule (run as Administrator): %v\n%s", err, string(output))
		log.Printf("To fix manually, run as Administrator:")
		log.Printf("  netsh advfirewall firewall add rule name=\"%s\" dir=in action=allow protocol=UDP program=\"%s\" enable=yes", ruleName, exePath)
	} else {
		log.Printf("Firewall rule added successfully")
	}
}
