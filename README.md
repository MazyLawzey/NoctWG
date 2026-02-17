# NoctWG - Nocturnal WireGuard

<img width="1240" height="600" alt="image" src="https://github.com/user-attachments/assets/f3f3b085-7dea-4177-8770-8fdbd2bb5393" />


A modern VPN protocol with Reverse Port Forwarding Tunnel (RPFT) support.

## Features

- **Secure VPN Protocol**: Based on Noise Protocol Framework with ChaCha20-Poly1305
- **RPFT (Reverse Port Forwarding Tunnel)**: Forward remote ports to local services
- **Cross-Platform Client**: Windows, Linux, macOS support
- **Web GUI**: Modern HTML/CSS/JS interface for easy management
- **Server Mode**: Dedicated server for production deployments

## Architecture

```
noctwg/
├── cmd/
│   ├── noctwg-client/    # VPN Client with GUI
│   └── noctwg-server/    # VPN Server
├── core/
│   ├── crypto/           # Cryptographic primitives
│   ├── protocol/         # VPN protocol implementation
│   └── tunnel/           # TUN device management
├── rpft/                 # Reverse Port Forwarding Tunnel
├── api/                  # HTTP API for GUI
├── gui/                  # HTML/CSS/JS Web Interface
└── config/               # Configuration management
```

## Quick Start

### Server
```bash
cd cmd/noctwg-server
go build
./noctwg-server --config /etc/noctwg/server.json
```

### Client
```bash
cd cmd/noctwg-client
go build
./noctwg-client --gui
```

## RPFT (Reverse Port Forwarding Tunnel)

RPFT allows you to expose local services through the VPN tunnel:

```json
{
  "rpft": {
    "tunnels": [
      {
        "name": "ssh",
        "local_port": 22,
        "remote_port": 2222,
        "protocol": "tcp"
      },
      {
        "name": "web",
        "local_port": 80,
        "remote_port": 8080,
        "protocol": "tcp"
      }
    ]
  }
}
```

## Configuration

### Client Configuration
```json
{
  "server": "vpn.example.com:51820",
  "private_key": "base64_encoded_private_key",
  "server_public_key": "base64_encoded_server_public_key",
  "allowed_ips": ["0.0.0.0/0", "::/0"],
  "dns": ["1.1.1.1", "8.8.8.8"],
  "rpft": {
    "enabled": true,
    "tunnels": []
  }
}
```

### Server Configuration
```json
{
  "listen": ":51820",
  "private_key": "base64_encoded_private_key",
  "allowed_peers": [],
  "rpft": {
    "enabled": true,
    "max_tunnels_per_peer": 10
  }
}

```

cya
