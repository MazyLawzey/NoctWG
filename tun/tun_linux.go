//go:build linux

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2025 NoctWG. All Rights Reserved.
 */

package tun

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"unsafe"
)

const (
	tunDevice     = "/dev/net/tun"
	ifnamsiz      = 16
	iffTun        = 0x0001
	iffNoPi       = 0x1000
	iffMultiQueue = 0x0100
)

// LinuxTUN implements Device interface for Linux
type LinuxTUN struct {
	name    string
	mtu     int
	fd      *os.File
	address net.IP
	netmask net.IPMask
	closed  bool
	mutex   sync.Mutex
}

type ifReq struct {
	Name  [ifnamsiz]byte
	Flags uint16
	pad   [24 - ifnamsiz - 2]byte
}

// createPlatformTUN creates a Linux TUN device
func createPlatformTUN(config *Config) (Device, error) {
	// Open /dev/net/tun
	fd, err := os.OpenFile(tunDevice, os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to open %s: %w (hint: run as root or check permissions)", tunDevice, err)
	}

	// Prepare ioctl request
	var req ifReq
	req.Flags = iffTun | iffNoPi

	name := config.Name
	if name == "" {
		name = "noctwg%d"
	}
	copy(req.Name[:], name)

	// TUNSETIFF ioctl
	_, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL,
		fd.Fd(),
		uintptr(0x400454ca), // TUNSETIFF
		uintptr(unsafe.Pointer(&req)),
	)
	if errno != 0 {
		fd.Close()
		return nil, fmt.Errorf("TUNSETIFF failed: %v", errno)
	}

	// Get actual interface name
	actualName := string(req.Name[:])
	for i, b := range req.Name {
		if b == 0 {
			actualName = string(req.Name[:i])
			break
		}
	}

	tun := &LinuxTUN{
		name:    actualName,
		mtu:     config.MTU,
		fd:      fd,
		address: config.Address,
		netmask: config.Netmask,
	}

	// Set MTU
	if err := tun.SetMTU(config.MTU); err != nil {
		fd.Close()
		return nil, fmt.Errorf("failed to set MTU: %w", err)
	}

	return tun, nil
}

func (t *LinuxTUN) Name() string {
	return t.name
}

func (t *LinuxTUN) MTU() int {
	return t.mtu
}

func (t *LinuxTUN) SetMTU(mtu int) error {
	t.mtu = mtu
	cmd := exec.Command("ip", "link", "set", "dev", t.name, "mtu", fmt.Sprintf("%d", mtu))
	return cmd.Run()
}

func (t *LinuxTUN) Read(p []byte) (int, error) {
	t.mutex.Lock()
	if t.closed {
		t.mutex.Unlock()
		return 0, ErrTUNClosed
	}
	t.mutex.Unlock()

	return t.fd.Read(p)
}

func (t *LinuxTUN) Write(p []byte) (int, error) {
	t.mutex.Lock()
	if t.closed {
		t.mutex.Unlock()
		return 0, ErrTUNClosed
	}
	t.mutex.Unlock()

	return t.fd.Write(p)
}

func (t *LinuxTUN) Close() error {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	if t.closed {
		return nil
	}
	t.closed = true

	return t.fd.Close()
}

func (t *LinuxTUN) Configure(address net.IP, netmask net.IPMask) error {
	t.address = address
	t.netmask = netmask

	ones, _ := netmask.Size()

	// Set IP address
	cmd := exec.Command("ip", "addr", "add",
		fmt.Sprintf("%s/%d", address.String(), ones),
		"dev", t.name)

	if err := cmd.Run(); err != nil {
		// Address might already exist, try replacing
		cmd = exec.Command("ip", "addr", "replace",
			fmt.Sprintf("%s/%d", address.String(), ones),
			"dev", t.name)
		return cmd.Run()
	}

	return nil
}

func (t *LinuxTUN) AddRoute(destination *net.IPNet) error {
	ones, _ := destination.Mask.Size()
	cmd := exec.Command("ip", "route", "add",
		fmt.Sprintf("%s/%d", destination.IP.String(), ones),
		"dev", t.name)
	return cmd.Run()
}

func (t *LinuxTUN) RemoveRoute(destination *net.IPNet) error {
	ones, _ := destination.Mask.Size()
	cmd := exec.Command("ip", "route", "del",
		fmt.Sprintf("%s/%d", destination.IP.String(), ones),
		"dev", t.name)
	return cmd.Run()
}

func (t *LinuxTUN) Up() error {
	cmd := exec.Command("ip", "link", "set", "dev", t.name, "up")
	return cmd.Run()
}

func (t *LinuxTUN) Down() error {
	cmd := exec.Command("ip", "link", "set", "dev", t.name, "down")
	return cmd.Run()
}
