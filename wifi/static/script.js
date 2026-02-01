// API Base URL
const API_BASE = '/api';

// Update status every 2 seconds
let statusInterval;

// Initialize page
document.addEventListener('DOMContentLoaded', () => {
    updateStatus();
    loadAttacks();
    startStatusUpdates();
});

// Start periodic status updates
function startStatusUpdates() {
    if (statusInterval) clearInterval(statusInterval);
    statusInterval = setInterval(() => {
        updateStatus();
        loadAttacks();
    }, 2000);
}

// Show notification
function showNotification(message, type = 'info') {
    const container = document.getElementById('notification-container');
    const notification = document.createElement('div');
    notification.className = `notification ${type}`;
    notification.textContent = message;
    
    container.appendChild(notification);
    
    setTimeout(() => {
        notification.style.opacity = '0';
        setTimeout(() => notification.remove(), 300);
    }, 3000);
}

// Initialize monitor
async function initializeMonitor() {
    const interface_name = document.getElementById('interface-input').value.trim();
    
    if (!interface_name) {
        showNotification('Please enter a network interface', 'error');
        return;
    }
    
    try {
        const response = await fetch(`${API_BASE}/initialize`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ interface: interface_name })
        });
        
        const data = await response.json();
        
        if (data.success) {
            showNotification(data.message, 'success');
            updateStatus();
        } else {
            showNotification(data.error || 'Initialization failed', 'error');
        }
    } catch (error) {
        showNotification('Error connecting to server', 'error');
        console.error(error);
    }
}

// Update status display
async function updateStatus() {
    try {
        const response = await fetch(`${API_BASE}/status`);
        const data = await response.json();
        
        // Update interface
        const interfaceStatus = document.getElementById('interface-status');
        interfaceStatus.textContent = data.interface || 'Not Initialized';
        
        // Update deauth status
        const deauthStatus = document.getElementById('deauth-status');
        if (data.deauth_running) {
            deauthStatus.innerHTML = '<span class="status-indicator status-online"></span> Running';
        } else {
            deauthStatus.innerHTML = '<span class="status-indicator status-offline"></span> Offline';
        }
        
        // Update WPS status
        const wpsStatus = document.getElementById('wps-status');
        if (data.wps_running) {
            wpsStatus.innerHTML = '<span class="status-indicator status-online"></span> Running';
        } else {
            wpsStatus.innerHTML = '<span class="status-indicator status-offline"></span> Offline';
        }
    } catch (error) {
        console.error('Error updating status:', error);
    }
}

// Start deauth detection
async function startDeauth() {
    try {
        const response = await fetch(`${API_BASE}/start/deauth`, { method: 'POST' });
        const data = await response.json();
        
        if (data.success) {
            showNotification('Deauth detection started', 'success');
            updateStatus();
        } else {
            showNotification(data.error || 'Failed to start deauth detection', 'error');
        }
    } catch (error) {
        showNotification('Error connecting to server', 'error');
        console.error(error);
    }
}

// Stop deauth detection
async function stopDeauth() {
    try {
        const response = await fetch(`${API_BASE}/stop/deauth`, { method: 'POST' });
        const data = await response.json();
        
        showNotification('Deauth detection stopped', 'success');
        updateStatus();
    } catch (error) {
        showNotification('Error connecting to server', 'error');
        console.error(error);
    }
}

// Start WPS detection
async function startWPS() {
    try {
        const response = await fetch(`${API_BASE}/start/wps`, { method: 'POST' });
        const data = await response.json();
        
        if (data.success) {
            showNotification('WPS detection started', 'success');
            updateStatus();
        } else {
            showNotification(data.error || 'Failed to start WPS detection', 'error');
        }
    } catch (error) {
        showNotification('Error connecting to server', 'error');
        console.error(error);
    }
}

// Stop WPS detection
async function stopWPS() {
    try {
        const response = await fetch(`${API_BASE}/stop/wps`, { method: 'POST' });
        const data = await response.json();
        
        showNotification('WPS detection stopped', 'success');
        updateStatus();
    } catch (error) {
        showNotification('Error connecting to server', 'error');
        console.error(error);
    }
}

// Start all detection
async function startAll() {
    try {
        const response = await fetch(`${API_BASE}/start/all`, { method: 'POST' });
        const data = await response.json();
        
        if (data.success) {
            showNotification('All detection started', 'success');
            updateStatus();
        } else {
            showNotification(data.error || 'Failed to start detection', 'error');
        }
    } catch (error) {
        showNotification('Error connecting to server', 'error');
        console.error(error);
    }
}

// Stop all detection
async function stopAll() {
    try {
        const response = await fetch(`${API_BASE}/stop/all`, { method: 'POST' });
        const data = await response.json();
        
        showNotification('All detection stopped', 'success');
        updateStatus();
    } catch (error) {
        showNotification('Error connecting to server', 'error');
        console.error(error);
    }
}

// Load attacks
async function loadAttacks() {
    try {
        const response = await fetch(`${API_BASE}/attacks`);
        const data = await response.json();
        
        const attackLog = document.getElementById('attack-log');
        const attackCount = document.getElementById('attack-count');
        
        attackCount.textContent = data.attacks.length;
        
        if (data.attacks.length === 0) {
            attackLog.innerHTML = '<div class="no-attacks">No attacks detected yet</div>';
            return;
        }
        
        attackLog.innerHTML = data.attacks.map(attack => {
            const date = new Date(attack.timestamp);
            const timeStr = date.toLocaleTimeString();
            const dateStr = date.toLocaleDateString();
            
            let details = '';
            if (attack.info.attacker_mac) {
                details += `<div><strong>Attacker:</strong> ${attack.info.attacker_mac}</div>`;
            }
            if (attack.info.target_ap) {
                details += `<div><strong>Target AP:</strong> ${attack.info.target_ap}</div>`;
            }
            if (attack.info.all_macs && attack.info.all_macs.length > 0) {
                details += `<div><strong>Devices:</strong> ${attack.info.all_macs.join(', ')}</div>`;
            }
            
            return `
                <div class="attack-entry ${attack.type}">
                    <div class="attack-header">
                        <span class="attack-type ${attack.type}">${attack.type.toUpperCase()}</span>
                        <span class="attack-time">${dateStr} ${timeStr}</span>
                    </div>
                    <div class="attack-details">
                        ${details}
                    </div>
                </div>
            `;
        }).join('');
    } catch (error) {
        console.error('Error loading attacks:', error);
    }
}

// Clear attack log
async function clearLog() {
    try {
        const response = await fetch(`${API_BASE}/attacks/clear`, { method: 'POST' });
        const data = await response.json();
        
        if (data.success) {
            showNotification('Attack log cleared', 'success');
            loadAttacks();
        }
    } catch (error) {
        showNotification('Error clearing log', 'error');
        console.error(error);
    }
}

// Allow Enter key in interface input
document.getElementById('interface-input')?.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') {
        initializeMonitor();
    }
});
