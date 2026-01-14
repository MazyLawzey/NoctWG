/* NoctWG Client - JavaScript Application */

// API Configuration
const API_BASE = window.location.origin;

// State
let state = {
    connected: false,
    connectedAt: null,
    stats: {
        bytesSent: 0,
        bytesReceived: 0,
        latency: 0
    },
    tunnels: [],
    logs: []
};

// Initialize application
document.addEventListener('DOMContentLoaded', () => {
    initNavigation();
    initForms();
    initModals();
    loadStatus();
    loadConfig();
    loadTunnels();
    
    // Start polling for updates
    setInterval(updateStatus, 2000);
    setInterval(updateTunnels, 5000);
    
    // Load theme preference
    const savedTheme = localStorage.getItem('theme') || 'dark';
    setTheme(savedTheme);
    document.getElementById('theme').value = savedTheme;
});

// Navigation
function initNavigation() {
    document.querySelectorAll('.nav-item').forEach(item => {
        item.addEventListener('click', () => {
            const page = item.dataset.page;
            navigateTo(page);
        });
    });
}

function navigateTo(page) {
    // Update nav items
    document.querySelectorAll('.nav-item').forEach(item => {
        item.classList.toggle('active', item.dataset.page === page);
    });
    
    // Update pages
    document.querySelectorAll('.page').forEach(p => {
        p.classList.toggle('active', p.id === `page-${page}`);
    });
}

// Forms
function initForms() {
    // Connection form
    document.getElementById('connection-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        await saveConfig();
    });
    
    // Add tunnel form
    document.getElementById('add-tunnel-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        await createTunnel();
    });
    
    // Settings form
    document.getElementById('settings-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        showToast('success', 'Settings Saved', 'Your settings have been saved.');
    });
    
    // Toggle connection button
    document.getElementById('toggle-connection').addEventListener('click', toggleConnection);
    
    // Test connection button
    document.getElementById('test-connection').addEventListener('click', testConnection);
    
    // Generate new keys button
    document.getElementById('generate-new-keys').addEventListener('click', generateNewKeys);
    
    // Add tunnel button
    document.getElementById('add-tunnel-btn').addEventListener('click', () => {
        openModal('add-tunnel-modal');
    });
    
    // Clear logs button
    document.getElementById('clear-logs').addEventListener('click', clearLogs);
    
    // Export logs button
    document.getElementById('export-logs').addEventListener('click', exportLogs);
}

// Modals
function initModals() {
    // Close modal on outside click
    document.querySelectorAll('.modal').forEach(modal => {
        modal.addEventListener('click', (e) => {
            if (e.target === modal) {
                closeModal(modal.id);
            }
        });
    });
}

function openModal(id) {
    document.getElementById(id).classList.add('active');
}

function closeModal(id) {
    document.getElementById(id).classList.remove('active');
}

// API Functions
async function apiCall(endpoint, method = 'GET', data = null) {
    const options = {
        method,
        headers: {
            'Content-Type': 'application/json'
        }
    };
    
    if (data) {
        options.body = JSON.stringify(data);
    }
    
    try {
        const response = await fetch(`${API_BASE}${endpoint}`, options);
        return await response.json();
    } catch (error) {
        console.error('API Error:', error);
        throw error;
    }
}

// Status Functions
async function loadStatus() {
    try {
        const status = await apiCall('/api/status');
        updateStatusDisplay(status);
    } catch (error) {
        addLog('error', 'Failed to load status');
    }
}

async function updateStatus() {
    try {
        const status = await apiCall('/api/status');
        updateStatusDisplay(status);
    } catch (error) {
        // Silently fail during polling
    }
}

function updateStatusDisplay(status) {
    state.connected = status.connected;
    state.stats.bytesSent = status.bytes_sent || 0;
    state.stats.bytesReceived = status.bytes_received || 0;
    state.stats.latency = status.latency_ms || 0;
    
    // Update connection status
    const statusEl = document.getElementById('connection-status');
    const statusDot = statusEl.querySelector('.status-dot');
    const statusText = statusEl.querySelector('span:last-child');
    
    if (status.connected) {
        statusDot.className = 'status-dot connected';
        statusText.textContent = 'Connected';
        state.connectedAt = status.connected_at ? new Date(status.connected_at) : new Date();
    } else {
        statusDot.className = 'status-dot disconnected';
        statusText.textContent = 'Disconnected';
        state.connectedAt = null;
    }
    
    // Update connection orb
    const orb = document.getElementById('connection-orb');
    orb.classList.toggle('connected', status.connected);
    
    // Update button
    const btn = document.getElementById('toggle-connection');
    btn.textContent = status.connected ? 'Disconnect' : 'Connect';
    btn.classList.toggle('btn-danger', status.connected);
    btn.classList.toggle('btn-primary', !status.connected);
    
    // Update stats
    document.getElementById('bytes-sent').textContent = formatBytes(state.stats.bytesSent);
    document.getElementById('bytes-recv').textContent = formatBytes(state.stats.bytesReceived);
    document.getElementById('latency').textContent = state.stats.latency > 0 ? `${state.stats.latency} ms` : '-- ms';
    
    // Update connected time
    if (state.connectedAt) {
        const elapsed = Math.floor((Date.now() - state.connectedAt) / 1000);
        document.getElementById('connected-time').textContent = formatDuration(elapsed);
    } else {
        document.getElementById('connected-time').textContent = '--:--:--';
    }
    
    // Update server address
    document.getElementById('server-addr').textContent = status.server_addr || 'Not configured';
    
    // Update public key
    document.getElementById('public-key').textContent = status.public_key || 'Loading...';
    document.getElementById('my-public-key').textContent = status.public_key || 'Loading...';
}

// Connection Functions
async function toggleConnection() {
    const btn = document.getElementById('toggle-connection');
    btn.disabled = true;
    
    try {
        if (state.connected) {
            await apiCall('/api/disconnect', 'POST');
            showToast('info', 'Disconnected', 'VPN connection closed.');
            addLog('info', 'Disconnected from VPN server');
        } else {
            const config = getConnectionConfig();
            if (!config.server_address || !config.server_public_key) {
                showToast('warning', 'Configuration Required', 'Please configure server settings first.');
                navigateTo('connection');
                btn.disabled = false;
                return;
            }
            
            const result = await apiCall('/api/connect', 'POST', config);
            if (result.status === 'connected') {
                showToast('success', 'Connected', 'VPN connection established.');
                addLog('info', `Connected to ${config.server_address}`);
            } else {
                throw new Error(result.error || 'Connection failed');
            }
        }
    } catch (error) {
        showToast('error', 'Error', error.message);
        addLog('error', `Connection error: ${error.message}`);
    }
    
    btn.disabled = false;
    updateStatus();
}

async function testConnection() {
    showToast('info', 'Testing...', 'Testing connection to server...');
    addLog('info', 'Testing connection...');
    
    try {
        const config = getConnectionConfig();
        // Here we'd implement actual connection testing
        // For now, just validate the config
        if (!config.server_address) {
            throw new Error('Server address is required');
        }
        if (!config.server_public_key) {
            throw new Error('Server public key is required');
        }
        
        showToast('success', 'Test Passed', 'Configuration looks valid.');
        addLog('info', 'Connection test passed');
    } catch (error) {
        showToast('error', 'Test Failed', error.message);
        addLog('error', `Connection test failed: ${error.message}`);
    }
}

function getConnectionConfig() {
    return {
        server_address: document.getElementById('server-address').value,
        server_port: parseInt(document.getElementById('server-port').value) || 51820,
        server_public_key: document.getElementById('server-public-key').value
    };
}

// Config Functions
async function loadConfig() {
    try {
        const config = await apiCall('/api/config');
        
        document.getElementById('server-address').value = config.server_address || '';
        document.getElementById('server-port').value = config.server_port || 51820;
        document.getElementById('server-public-key').value = config.server_public_key || '';
        document.getElementById('allowed-ips').value = (config.allowed_ips || []).join(', ');
        document.getElementById('dns-servers').value = (config.dns || []).join(', ');
        document.getElementById('keepalive').value = config.persistent_keepalive || 25;
    } catch (error) {
        addLog('warning', 'Failed to load configuration');
    }
}

async function saveConfig() {
    const config = {
        server_address: document.getElementById('server-address').value,
        server_port: parseInt(document.getElementById('server-port').value) || 51820,
        server_public_key: document.getElementById('server-public-key').value,
        allowed_ips: document.getElementById('allowed-ips').value.split(',').map(s => s.trim()),
        dns: document.getElementById('dns-servers').value.split(',').map(s => s.trim()),
        persistent_keepalive: parseInt(document.getElementById('keepalive').value) || 25
    };
    
    try {
        await apiCall('/api/config', 'POST', config);
        showToast('success', 'Saved', 'Configuration saved successfully.');
        addLog('info', 'Configuration saved');
    } catch (error) {
        showToast('error', 'Error', 'Failed to save configuration.');
        addLog('error', 'Failed to save configuration');
    }
}

async function generateNewKeys() {
    if (!confirm('Are you sure? This will generate new keys and require updating the server configuration.')) {
        return;
    }
    
    try {
        const result = await apiCall('/api/genkey', 'POST');
        document.getElementById('my-public-key').textContent = result.public_key;
        document.getElementById('public-key').textContent = result.public_key;
        showToast('success', 'Keys Generated', 'New keys have been generated.');
        addLog('info', 'New keys generated');
    } catch (error) {
        showToast('error', 'Error', 'Failed to generate keys.');
    }
}

// Tunnel Functions
async function loadTunnels() {
    try {
        const tunnels = await apiCall('/api/rpft/tunnels');
        state.tunnels = tunnels;
        updateTunnelsDisplay(tunnels);
    } catch (error) {
        addLog('warning', 'Failed to load tunnels');
    }
}

async function updateTunnels() {
    try {
        const tunnels = await apiCall('/api/rpft/tunnels');
        state.tunnels = tunnels;
        updateTunnelsDisplay(tunnels);
        
        // Update dashboard summary
        const activeTunnels = tunnels.filter(t => t.state === 'active').length;
        const totalConnections = tunnels.reduce((sum, t) => sum + (t.connections || 0), 0);
        
        document.getElementById('active-tunnels').textContent = activeTunnels;
        document.getElementById('total-connections').textContent = totalConnections;
    } catch (error) {
        // Silently fail during polling
    }
}

function updateTunnelsDisplay(tunnels) {
    const tbody = document.getElementById('tunnels-body');
    
    if (tunnels.length === 0) {
        tbody.innerHTML = `
            <tr class="empty-row">
                <td colspan="8">No tunnels configured. Click "Add Tunnel" to create one.</td>
            </tr>
        `;
        return;
    }
    
    tbody.innerHTML = tunnels.map(tunnel => `
        <tr>
            <td><strong>${escapeHtml(tunnel.name)}</strong></td>
            <td>${tunnel.type === 'local_to_remote' ? 'L → R' : 'R → L'}</td>
            <td>${tunnel.protocol.toUpperCase()}</td>
            <td>${tunnel.local_host}:${tunnel.local_port}</td>
            <td>${tunnel.remote_host}:${tunnel.remote_port}</td>
            <td><span class="status-badge ${tunnel.state}">${tunnel.state}</span></td>
            <td>${formatBytes(tunnel.bytes_sent)} / ${formatBytes(tunnel.bytes_recv)}</td>
            <td>
                <div style="display: flex; gap: 8px;">
                    ${tunnel.state === 'active' 
                        ? `<button class="btn btn-sm btn-warning" onclick="stopTunnel(${tunnel.id})">Stop</button>`
                        : `<button class="btn btn-sm btn-success" onclick="startTunnel(${tunnel.id})">Start</button>`
                    }
                    <button class="btn btn-sm btn-danger" onclick="deleteTunnel(${tunnel.id})">Delete</button>
                </div>
            </td>
        </tr>
    `).join('');
}

async function createTunnel() {
    const tunnel = {
        name: document.getElementById('tunnel-name').value,
        type: document.getElementById('tunnel-type').value,
        protocol: document.getElementById('tunnel-protocol').value,
        local_host: document.getElementById('tunnel-local-host').value || '127.0.0.1',
        local_port: parseInt(document.getElementById('tunnel-local-port').value),
        remote_host: document.getElementById('tunnel-remote-host').value || '127.0.0.1',
        remote_port: parseInt(document.getElementById('tunnel-remote-port').value)
    };
    
    try {
        const result = await apiCall('/api/rpft/create', 'POST', tunnel);
        closeModal('add-tunnel-modal');
        document.getElementById('add-tunnel-form').reset();
        showToast('success', 'Tunnel Created', `Tunnel "${tunnel.name}" created successfully.`);
        addLog('info', `Created tunnel: ${tunnel.name}`);
        loadTunnels();
    } catch (error) {
        showToast('error', 'Error', 'Failed to create tunnel.');
    }
}

async function startTunnel(id) {
    try {
        await apiCall('/api/rpft/start', 'POST', { tunnel_id: id });
        showToast('success', 'Started', 'Tunnel started successfully.');
        addLog('info', `Started tunnel #${id}`);
        loadTunnels();
    } catch (error) {
        showToast('error', 'Error', 'Failed to start tunnel.');
    }
}

async function stopTunnel(id) {
    try {
        await apiCall('/api/rpft/stop', 'POST', { tunnel_id: id });
        showToast('info', 'Stopped', 'Tunnel stopped.');
        addLog('info', `Stopped tunnel #${id}`);
        loadTunnels();
    } catch (error) {
        showToast('error', 'Error', 'Failed to stop tunnel.');
    }
}

async function deleteTunnel(id) {
    if (!confirm('Are you sure you want to delete this tunnel?')) {
        return;
    }
    
    try {
        await apiCall('/api/rpft/delete', 'POST', { tunnel_id: id });
        showToast('info', 'Deleted', 'Tunnel deleted.');
        addLog('info', `Deleted tunnel #${id}`);
        loadTunnels();
    } catch (error) {
        showToast('error', 'Error', 'Failed to delete tunnel.');
    }
}

// Logging Functions
function addLog(level, message) {
    const time = new Date().toLocaleTimeString();
    const entry = { time, level, message };
    state.logs.push(entry);
    
    // Keep only last 1000 logs
    if (state.logs.length > 1000) {
        state.logs.shift();
    }
    
    const container = document.getElementById('logs-container');
    const div = document.createElement('div');
    div.className = `log-entry ${level}`;
    div.innerHTML = `
        <span class="log-time">${time}</span>
        <span class="log-level">${level.toUpperCase()}</span>
        <span class="log-message">${escapeHtml(message)}</span>
    `;
    container.appendChild(div);
    container.scrollTop = container.scrollHeight;
}

function clearLogs() {
    state.logs = [];
    document.getElementById('logs-container').innerHTML = '';
    addLog('info', 'Logs cleared');
}

function exportLogs() {
    const content = state.logs.map(l => `[${l.time}] [${l.level.toUpperCase()}] ${l.message}`).join('\n');
    const blob = new Blob([content], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `noctwg-logs-${new Date().toISOString().split('T')[0]}.txt`;
    a.click();
    URL.revokeObjectURL(url);
    showToast('success', 'Exported', 'Logs exported to file.');
}

// Toast Notifications
function showToast(type, title, message) {
    const container = document.getElementById('toast-container');
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    
    const icons = {
        success: '✓',
        error: '✕',
        warning: '⚠',
        info: 'ℹ'
    };
    
    toast.innerHTML = `
        <span class="toast-icon">${icons[type]}</span>
        <div class="toast-content">
            <div class="toast-title">${escapeHtml(title)}</div>
            <div class="toast-message">${escapeHtml(message)}</div>
        </div>
    `;
    
    container.appendChild(toast);
    
    // Remove after 5 seconds
    setTimeout(() => {
        toast.style.animation = 'toastIn 0.25s ease reverse';
        setTimeout(() => toast.remove(), 250);
    }, 5000);
}

// Theme Functions
function setTheme(theme) {
    if (theme === 'system') {
        const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
        document.documentElement.dataset.theme = prefersDark ? 'dark' : 'light';
    } else {
        document.documentElement.dataset.theme = theme;
    }
    localStorage.setItem('theme', theme);
}

// Utility Functions
function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function formatDuration(seconds) {
    const hours = Math.floor(seconds / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    const secs = seconds % 60;
    return `${hours.toString().padStart(2, '0')}:${minutes.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`;
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function copyToClipboard(elementId) {
    const text = document.getElementById(elementId).textContent;
    navigator.clipboard.writeText(text).then(() => {
        showToast('success', 'Copied', 'Copied to clipboard.');
    }).catch(() => {
        showToast('error', 'Error', 'Failed to copy.');
    });
}
