//go:build windows

/* SPDX-License-Identifier: GPL-3.0
 *
 * Copyright (C) 2025 NoctWG. All Rights Reserved.
 */

package tun

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
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
	// Determine architecture suffix
	arch := runtime.GOARCH
	if arch == "386" {
		arch = "x86"
	}

	// Get the directory of the current executable
	exePath, _ := os.Executable()
	exeDir := filepath.Dir(exePath)

	// Build a comprehensive list of search paths
	searchPaths := []string{
		// Same directory as executable
		filepath.Join(exeDir, "wintun.dll"),
		// wintun subfolder next to executable
		filepath.Join(exeDir, "wintun", "bin", arch, "wintun.dll"),
		// Parent directory (when exe is in bin/)
		filepath.Join(exeDir, "..", "wintun", "bin", arch, "wintun.dll"),
		// Current working directory
		"wintun.dll",
		filepath.Join("wintun", "bin", arch, "wintun.dll"),
		// Fallback: try all architectures from cwd
		filepath.Join("wintun", "bin", "amd64", "wintun.dll"),
		filepath.Join("wintun", "bin", "arm64", "wintun.dll"),
		filepath.Join("wintun", "bin", "x86", "wintun.dll"),
	}

	for _, path := range searchPaths {
		absPath, err := filepath.Abs(path)
		if err != nil {
			continue
		}
		// Check if file exists first
		if _, err := os.Stat(absPath); err != nil {
			continue
		}
		dll := windows.NewLazyDLL(absPath)
		if loadErr := dll.Load(); loadErr == nil {
			fmt.Printf("[TUN] Loaded wintun.dll from: %s\n", absPath)
			wintunDLL = dll
			break
		}
	}

	if wintunDLL == nil {
		fmt.Printf("[TUN] WARNING: wintun.dll not found in any of these locations:\n")
		for _, path := range searchPaths {
			absPath, _ := filepath.Abs(path)
			fmt.Printf("[TUN]   %s\n", absPath)
		}
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

// isAdmin checks if the process is running with Administrator privileges
func isAdmin() bool {
	_, err := os.Open("\\\\.\\PHYSICALDRIVE0")
	if err != nil {
		return false
	}
	return true
}

// createPlatformTUN creates a Windows TUN device using WinTUN
func createPlatformTUN(config *Config) (Device, error) {
	if wintunDLL == nil {
		return nil, fmt.Errorf(
			"wintun.dll not found!\n\n" +
				"Please follow these steps:\n" +
				"1. Download wintun from: https://www.wintun.net/\n" +
				"2. Extract the DLL for your architecture (amd64/x86/arm64)\n" +
				"3. Place wintun.dll next to noctwg-client.exe or in wintun/bin/<arch>/\n")
	}

	if !isAdmin() {
		return nil, fmt.Errorf(
			"creating a TUN adapter requires Administrator privileges.\n" +
				"Please run noctwg-client.exe as Administrator (right-click -> Run as administrator)")
	}

	fmt.Printf("[TUN] Creating WinTUN adapter...\n")

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
	fmt.Printf("[TUN] Calling WintunCreateAdapter(%s, %s)...\n", name, wintunPoolName)
	ret, _, err := wintunCreateAdapter.Call(
		uintptr(unsafe.Pointer(namePtr)),
		uintptr(unsafe.Pointer(poolPtr)),
		0, // No GUID
	)

	if ret == 0 {
		return nil, fmt.Errorf("failed to create WinTUN adapter: %v (ensure running as Administrator)", err)
	}
	fmt.Printf("[TUN] Adapter created successfully (handle=%x)\n", ret)

	adapter := ret

	// Get LUID
	var luid uint64
	wintunGetAdapterLUID.Call(adapter, uintptr(unsafe.Pointer(&luid)))

	// Start session (ring size = 0x400000 = 4MB)
	fmt.Printf("[TUN] Starting WinTUN session...\n")
	ret, _, err = wintunStartSession.Call(adapter, 0x400000)
	if ret == 0 {
		wintunCloseAdapter.Call(adapter)
		return nil, fmt.Errorf("failed to start WinTUN session: %v", err)
	}
	fmt.Printf("[TUN] Session started (handle=%x)\n", ret)

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

	fmt.Printf("[TUN] Configuring interface %s: address=%s/%d\n", t.name, address.String(), ones)

	// Set IP address using netsh
	cmd := exec.Command("netsh", "interface", "ipv4", "set", "address",
		fmt.Sprintf("name=%s", t.name),
		"source=static",
		fmt.Sprintf("address=%s", address.String()),
		fmt.Sprintf("mask=%d.%d.%d.%d", netmask[0], netmask[1], netmask[2], netmask[3]),
	)
	output, err := cmd.CombinedOutput()
	fmt.Printf("[TUN] netsh set address result: %s (err=%v)\n", string(output), err)

	if err != nil {
		// Try alternative method
		fmt.Printf("[TUN] Trying alternative method: netsh add address\n")
		cmd = exec.Command("netsh", "interface", "ipv4", "add", "address",
			t.name, address.String(), fmt.Sprintf("%d", ones))
		output, err = cmd.CombinedOutput()
		fmt.Printf("[TUN] netsh add address result: %s (err=%v)\n", string(output), err)
		if err != nil {
			return fmt.Errorf("failed to configure interface: %s", string(output))
		}
	}

	// NOTE: Default route is added separately via AddDefaultRoute()
	// It must be called AFTER the interface is Up()
	return nil
}

// AddDefaultRoute adds the 0.0.0.0/0 default route through the VPN gateway.
// Must be called AFTER Configure() and Up() — Windows rejects routes on inactive interfaces.
func (t *WinTUN) AddDefaultRoute() error {
	gatewayIP := net.IP(make([]byte, len(t.address)))
	copy(gatewayIP, t.address)
	gatewayIP[len(gatewayIP)-1] = 1 // 10.0.0.1

	ifIdx := t.getInterfaceIndex()
	fmt.Printf("[TUN] Adding default route: 0.0.0.0/0 via %s iface=%s (idx=%d)\n", gatewayIP, t.name, ifIdx)

	// Method 1: route add (most reliable on Windows)
	args := []string{"add", "0.0.0.0", "mask", "0.0.0.0", gatewayIP.String(), "metric", "5"}
	if ifIdx > 0 {
		args = append(args, "if", fmt.Sprintf("%d", ifIdx))
	}
	cmd := exec.Command("route", args...)
	output, err := cmd.CombinedOutput()
	fmt.Printf("[TUN] route add result: %s (err=%v)\n", strings.TrimSpace(string(output)), err)
	if err == nil {
		return nil
	}

	// Method 2: netsh
	fmt.Printf("[TUN] Trying netsh fallback...\n")
	cmd = exec.Command("netsh", "interface", "ipv4", "add", "route",
		"prefix=0.0.0.0/0",
		fmt.Sprintf("interface=%s", t.name),
		fmt.Sprintf("nexthop=%s", gatewayIP.String()),
		"metric=5",
		"store=active",
	)
	output, err = cmd.CombinedOutput()
	fmt.Printf("[TUN] netsh add route result: %s (err=%v)\n", strings.TrimSpace(string(output)), err)
	if err == nil {
		return nil
	}

	// Method 3: PowerShell
	fmt.Printf("[TUN] Trying PowerShell fallback...\n")
	psCmd := fmt.Sprintf("New-NetRoute -DestinationPrefix '0.0.0.0/0' -InterfaceAlias '%s' -NextHop '%s' -RouteMetric 5 -ErrorAction SilentlyContinue",
		t.name, gatewayIP.String())
	cmd = exec.Command("powershell", "-Command", psCmd)
	output, err = cmd.CombinedOutput()
	fmt.Printf("[TUN] PowerShell route result: %s (err=%v)\n", strings.TrimSpace(string(output)), err)

	if err != nil {
		return fmt.Errorf("all methods to add default route failed")
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

// getInterfaceIndex returns the Windows interface index for route commands
func (t *WinTUN) getInterfaceIndex() int {
	ifaces, err := net.Interfaces()
	if err != nil {
		return 0
	}
	for _, iface := range ifaces {
		if iface.Name == t.name {
			return iface.Index
		}
	}
	return 0
}

// Ensure syscall is used (for build)
var _ = syscall.EINVAL
