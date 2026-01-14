//go:build windows

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2025 NoctWG. All Rights Reserved.
 */

package tun

import (
	"errors"
	"fmt"
	"net"
	"os/exec"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	wintunPoolName = "NoctWG"
)

var (
	wintunDLL *windows.LazyDLL

	wintunCreateAdapter           *windows.LazyProc
	wintunCloseAdapter            *windows.LazyProc
	wintunGetAdapterLUID          *windows.LazyProc
	wintunStartSession            *windows.LazyProc
	wintunEndSession              *windows.LazyProc
	wintunGetRunningDriverVersion *windows.LazyProc
	wintunReceivePacket           *windows.LazyProc
	wintunReleaseReceivePacket    *windows.LazyProc
	wintunAllocateSendPacket      *windows.LazyProc
	wintunSendPacket              *windows.LazyProc
	wintunGetReadWaitEvent        *windows.LazyProc
)

func init() {
	// Try to load wintun.dll from different locations
	searchPaths := []string{
		"wintun.dll",
		"wintun/bin/amd64/wintun.dll",
		"./wintun/bin/amd64/wintun.dll",
		"./wintun/bin/arm64/wintun.dll",
		"./wintun/bin/x86/wintun.dll",
		"../wintun/bin/amd64/wintun.dll",
	}

	for _, path := range searchPaths {
		dll := windows.NewLazyDLL(path)
		if loadErr := dll.Load(); loadErr == nil {
			wintunDLL = dll
			break
		}
	}

	if wintunDLL == nil {
		// Don't log here, we'll handle it in createPlatformTUN
		return
	}

	wintunCreateAdapter = wintunDLL.NewProc("WintunCreateAdapter")
	wintunCloseAdapter = wintunDLL.NewProc("WintunCloseAdapter")
	wintunGetAdapterLUID = wintunDLL.NewProc("WintunGetAdapterLUID")
	wintunStartSession = wintunDLL.NewProc("WintunStartSession")
	wintunEndSession = wintunDLL.NewProc("WintunEndSession")
	wintunGetRunningDriverVersion = wintunDLL.NewProc("WintunGetRunningDriverVersion")
	wintunReceivePacket = wintunDLL.NewProc("WintunReceivePacket")
	wintunReleaseReceivePacket = wintunDLL.NewProc("WintunReleaseReceivePacket")
	wintunAllocateSendPacket = wintunDLL.NewProc("WintunAllocateSendPacket")
	wintunSendPacket = wintunDLL.NewProc("WintunSendPacket")
	wintunGetReadWaitEvent = wintunDLL.NewProc("WintunGetReadWaitEvent")
}

// WinTUN implements Device interface for Windows
type WinTUN struct {
	name      string
	mtu       int
	adapter   uintptr
	session   uintptr
	readEvent windows.Handle
	luid      uint64

	address net.IP
	netmask net.IPMask

	closed bool
	mutex  sync.Mutex
}

// createPlatformTUN creates a Windows TUN device using WinTUN
func createPlatformTUN(config *Config) (Device, error) {
	if wintunDLL == nil {
		return nil, errors.New(
			"wintun.dll not found!\n\n" +
				"Please follow these steps:\n" +
				"1. Download wintun from: https://www.wintun.net/\n" +
				"2. Extract the DLL for your architecture (amd64/x86/arm64)\n" +
				"3. Place wintun.dll in the same directory as noctwg-client.exe\n\n" +
				"Or create a folder structure: wintun/bin/amd64/wintun.dll\n")
	}

	if err := wintunDLL.Load(); err != nil {
		return nil, fmt.Errorf("failed to load wintun.dll: %w (is the WinTUN driver installed?)", err)
	}

	name := config.Name
	if name == "" {
		name = "NoctWG"
	}

	// Convert strings to UTF16
	namePtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}

	poolPtr, err := windows.UTF16PtrFromString(wintunPoolName)
	if err != nil {
		return nil, err
	}

	// Create adapter
	ret, _, err := wintunCreateAdapter.Call(
		uintptr(unsafe.Pointer(namePtr)),
		uintptr(unsafe.Pointer(poolPtr)),
		0, // No GUID
	)

	if ret == 0 {
		return nil, fmt.Errorf("failed to create WinTUN adapter: %v", err)
	}

	adapter := ret

	// Get LUID
	var luid uint64
	wintunGetAdapterLUID.Call(adapter, uintptr(unsafe.Pointer(&luid)))

	// Start session (ring size = 0x400000 = 4MB)
	ret, _, err = wintunStartSession.Call(adapter, 0x400000)
	if ret == 0 {
		wintunCloseAdapter.Call(adapter)
		return nil, fmt.Errorf("failed to start WinTUN session: %v", err)
	}

	session := ret

	// Get read event
	ret, _, _ = wintunGetReadWaitEvent.Call(session)
	readEvent := windows.Handle(ret)

	tun := &WinTUN{
		name:      name,
		mtu:       config.MTU,
		adapter:   adapter,
		session:   session,
		readEvent: readEvent,
		luid:      luid,
		address:   config.Address,
		netmask:   config.Netmask,
	}

	return tun, nil
}

func (t *WinTUN) Name() string {
	return t.name
}

func (t *WinTUN) MTU() int {
	return t.mtu
}

func (t *WinTUN) SetMTU(mtu int) error {
	t.mtu = mtu
	// WinTUN MTU is set via netsh
	cmd := exec.Command("netsh", "interface", "ipv4", "set", "subinterface",
		t.name, fmt.Sprintf("mtu=%d", mtu), "store=persistent")
	return cmd.Run()
}

func (t *WinTUN) Read(p []byte) (int, error) {
	t.mutex.Lock()
	if t.closed {
		t.mutex.Unlock()
		return 0, ErrTUNClosed
	}
	t.mutex.Unlock()

	for {
		// Wait for packet
		windows.WaitForSingleObject(t.readEvent, windows.INFINITE)

		var packetSize uint32
		ret, _, _ := wintunReceivePacket.Call(
			t.session,
			uintptr(unsafe.Pointer(&packetSize)),
		)

		if ret == 0 {
			continue // No packet, retry
		}

		packet := unsafe.Slice((*byte)(unsafe.Pointer(ret)), packetSize)
		n := copy(p, packet)

		wintunReleaseReceivePacket.Call(t.session, ret)

		return n, nil
	}
}

func (t *WinTUN) Write(p []byte) (int, error) {
	t.mutex.Lock()
	if t.closed {
		t.mutex.Unlock()
		return 0, ErrTUNClosed
	}
	t.mutex.Unlock()

	packetSize := uint32(len(p))
	ret, _, err := wintunAllocateSendPacket.Call(
		t.session,
		uintptr(packetSize),
	)

	if ret == 0 {
		return 0, fmt.Errorf("failed to allocate send packet: %v", err)
	}

	packet := unsafe.Slice((*byte)(unsafe.Pointer(ret)), packetSize)
	copy(packet, p)

	wintunSendPacket.Call(t.session, ret)

	return len(p), nil
}

func (t *WinTUN) Close() error {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	if t.closed {
		return nil
	}
	t.closed = true

	if t.session != 0 {
		wintunEndSession.Call(t.session)
	}
	if t.adapter != 0 {
		wintunCloseAdapter.Call(t.adapter)
	}

	return nil
}

func (t *WinTUN) Configure(address net.IP, netmask net.IPMask) error {
	t.address = address
	t.netmask = netmask

	// Calculate prefix length
	ones, _ := netmask.Size()

	// Set IP address using netsh
	cmd := exec.Command("netsh", "interface", "ipv4", "set", "address",
		fmt.Sprintf("name=%s", t.name),
		"source=static",
		fmt.Sprintf("address=%s", address.String()),
		fmt.Sprintf("mask=%d.%d.%d.%d", netmask[0], netmask[1], netmask[2], netmask[3]),
	)

	if err := cmd.Run(); err != nil {
		// Try alternative method
		cmd = exec.Command("netsh", "interface", "ipv4", "add", "address",
			t.name, address.String(), fmt.Sprintf("%d", ones))
		if err := cmd.Run(); err != nil {
			return err
		}
	}

	// Set default gateway to server (typically x.x.x.1)
	gatewayIP := net.IP(make([]byte, len(address)))
	copy(gatewayIP, address)
	gatewayIP[len(gatewayIP)-1] = 1 // Set last octet to 1 (10.0.0.1)

	fmt.Printf("[TUN] Setting gateway to %s\n", gatewayIP.String())

	cmd = exec.Command("netsh", "interface", "ipv4", "add", "route",
		"destination=0.0.0.0/0",
		fmt.Sprintf("interface=%s", t.name),
		fmt.Sprintf("gateway=%s", gatewayIP.String()),
		"metric=10",
	)

	if err := cmd.Run(); err != nil {
		fmt.Printf("[TUN] Warning: failed to set default route: %v\n", err)
		// Don't fail completely, connection might still work
	}

	return nil
}

func (t *WinTUN) AddRoute(destination *net.IPNet) error {
	cmd := exec.Command("route", "add",
		destination.IP.String(),
		"mask", fmt.Sprintf("%d.%d.%d.%d",
			destination.Mask[0], destination.Mask[1],
			destination.Mask[2], destination.Mask[3]),
		t.address.String(),
		"metric", "1",
	)
	return cmd.Run()
}

func (t *WinTUN) RemoveRoute(destination *net.IPNet) error {
	cmd := exec.Command("route", "delete", destination.IP.String())
	return cmd.Run()
}

func (t *WinTUN) Up() error {
	cmd := exec.Command("netsh", "interface", "set", "interface", t.name, "enable")
	return cmd.Run()
}

func (t *WinTUN) Down() error {
	cmd := exec.Command("netsh", "interface", "set", "interface", t.name, "disable")
	return cmd.Run()
}

// Ensure syscall is used (for build)
var _ = syscall.EINVAL
