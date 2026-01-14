//go:build darwin

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2025 NoctWG. All Rights Reserved.
 */

package tun

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"unsafe"
)

const (
	utunControlName = "com.apple.net.utun_control"
	utunOptIfName   = 2
)

// DarwinTUN implements Device interface for macOS
type DarwinTUN struct {
	name    string
	mtu     int
	fd      int
	address net.IP
	netmask net.IPMask
	closed  bool
	mutex   sync.Mutex
}

// sockaddr_ctl for macOS
type sockaddrCtl struct {
	scLen      uint8
	scFamily   uint8
	ssSysaddr  uint16
	scID       uint32
	scUnit     uint32
	scReserved [5]uint32
}

// ctl_info for CTLIOCGINFO
type ctlInfo struct {
	ctlID   uint32
	ctlName [96]byte
}

// createPlatformTUN creates a macOS utun device
func createPlatformTUN(config *Config) (Device, error) {
	// Create socket
	fd, err := syscall.Socket(syscall.AF_SYSTEM, syscall.SOCK_DGRAM, 2) // SYSPROTO_CONTROL = 2
	if err != nil {
		return nil, fmt.Errorf("failed to create socket: %w", err)
	}

	// Get control ID
	var info ctlInfo
	copy(info.ctlName[:], utunControlName)

	_, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL,
		uintptr(fd),
		uintptr(0xc0644e03), // CTLIOCGINFO
		uintptr(unsafe.Pointer(&info)),
	)
	if errno != 0 {
		syscall.Close(fd)
		return nil, fmt.Errorf("CTLIOCGINFO failed: %v", errno)
	}

	// Connect to control
	sc := sockaddrCtl{
		scLen:     uint8(unsafe.Sizeof(sockaddrCtl{})),
		scFamily:  syscall.AF_SYSTEM,
		ssSysaddr: 2, // AF_SYS_CONTROL
		scID:      info.ctlID,
		scUnit:    0, // Auto-assign unit number
	}

	_, _, errno = syscall.Syscall(
		syscall.SYS_CONNECT,
		uintptr(fd),
		uintptr(unsafe.Pointer(&sc)),
		uintptr(sc.scLen),
	)
	if errno != 0 {
		syscall.Close(fd)
		return nil, fmt.Errorf("connect failed: %v", errno)
	}

	// Get interface name
	var ifName [32]byte
	ifNameLen := uint32(len(ifName))

	_, _, errno = syscall.Syscall6(
		syscall.SYS_GETSOCKOPT,
		uintptr(fd),
		2, // SYSPROTO_CONTROL
		utunOptIfName,
		uintptr(unsafe.Pointer(&ifName[0])),
		uintptr(unsafe.Pointer(&ifNameLen)),
		0,
	)
	if errno != 0 {
		syscall.Close(fd)
		return nil, fmt.Errorf("getsockopt failed: %v", errno)
	}

	name := string(ifName[:ifNameLen-1])

	// Set non-blocking
	if err := syscall.SetNonblock(fd, false); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("failed to set blocking mode: %w", err)
	}

	tun := &DarwinTUN{
		name:    name,
		mtu:     config.MTU,
		fd:      fd,
		address: config.Address,
		netmask: config.Netmask,
	}

	return tun, nil
}

func (t *DarwinTUN) Name() string {
	return t.name
}

func (t *DarwinTUN) MTU() int {
	return t.mtu
}

func (t *DarwinTUN) SetMTU(mtu int) error {
	t.mtu = mtu
	cmd := exec.Command("ifconfig", t.name, "mtu", fmt.Sprintf("%d", mtu))
	return cmd.Run()
}

func (t *DarwinTUN) Read(p []byte) (int, error) {
	t.mutex.Lock()
	if t.closed {
		t.mutex.Unlock()
		return 0, ErrTUNClosed
	}
	t.mutex.Unlock()

	// macOS utun prepends 4-byte protocol header
	buf := make([]byte, t.mtu+4)
	n, err := syscall.Read(t.fd, buf)
	if err != nil {
		return 0, err
	}

	if n <= 4 {
		return 0, ErrInvalidPacket
	}

	// Skip 4-byte header
	copy(p, buf[4:n])
	return n - 4, nil
}

func (t *DarwinTUN) Write(p []byte) (int, error) {
	t.mutex.Lock()
	if t.closed {
		t.mutex.Unlock()
		return 0, ErrTUNClosed
	}
	t.mutex.Unlock()

	// Prepend 4-byte protocol header
	buf := make([]byte, len(p)+4)

	// Determine protocol from IP version
	if len(p) > 0 {
		version := p[0] >> 4
		if version == 4 {
			binary.BigEndian.PutUint32(buf[:4], syscall.AF_INET)
		} else if version == 6 {
			binary.BigEndian.PutUint32(buf[:4], syscall.AF_INET6)
		}
	}

	copy(buf[4:], p)

	n, err := syscall.Write(t.fd, buf)
	if err != nil {
		return 0, err
	}

	return n - 4, nil
}

func (t *DarwinTUN) Close() error {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	if t.closed {
		return nil
	}
	t.closed = true

	return syscall.Close(t.fd)
}

func (t *DarwinTUN) Configure(address net.IP, netmask net.IPMask) error {
	t.address = address
	t.netmask = netmask

	ones, _ := netmask.Size()

	// Set IP address using ifconfig
	// For point-to-point, we need a destination address
	destIP := make(net.IP, len(address))
	copy(destIP, address)
	destIP[3] = 1 // e.g., 10.0.0.2 -> 10.0.0.1

	cmd := exec.Command("ifconfig", t.name,
		address.String(), destIP.String(),
		"netmask", fmt.Sprintf("0x%02x%02x%02x%02x", netmask[0], netmask[1], netmask[2], netmask[3]))

	if err := cmd.Run(); err != nil {
		// Try alternative format
		cmd = exec.Command("ifconfig", t.name, "inet",
			fmt.Sprintf("%s/%d", address.String(), ones),
			destIP.String())
		return cmd.Run()
	}

	return nil
}

func (t *DarwinTUN) AddRoute(destination *net.IPNet) error {
	ones, _ := destination.Mask.Size()

	// Use route command
	cmd := exec.Command("route", "-n", "add", "-net",
		fmt.Sprintf("%s/%d", destination.IP.String(), ones),
		"-interface", t.name)
	return cmd.Run()
}

func (t *DarwinTUN) RemoveRoute(destination *net.IPNet) error {
	ones, _ := destination.Mask.Size()

	cmd := exec.Command("route", "-n", "delete", "-net",
		fmt.Sprintf("%s/%d", destination.IP.String(), ones))
	return cmd.Run()
}

func (t *DarwinTUN) Up() error {
	cmd := exec.Command("ifconfig", t.name, "up")
	return cmd.Run()
}

func (t *DarwinTUN) Down() error {
	cmd := exec.Command("ifconfig", t.name, "down")
	return cmd.Run()
}

// Ensure os is used (for potential future file operations)
var _ = os.DevNull
