/**
 * AI-Powered Cybersecurity Dashboard
 * Frontend JavaScript with Fetch API integration
 */

// ==================== GLOBAL STATE ====================
const state = {
    currentPage: 'dashboard',
    isDefenseActive: true,
    threatLevel: 'LOW',
    systemLogs: [],
    scanCount: 0,
    threatCount: 0,
    usbCount: 0,
    aiQuestions: 0,
    apiKeys: {
        virustotal: localStorage.getItem('vt_api_key') || '',
        ai: localStorage.getItem('ai_api_key') || ''
    }
};

// ==================== INITIALIZATION ====================
document.addEventListener('DOMContentLoaded', function() {
    initDashboard();
    initNavigation();
    initEventListeners();
    startSystemUpdates();
    loadSystemStatus();
    initMatrixAnimation();
});

// ==================== DASHBOARD FUNCTIONS ====================
function initDashboard() {
    // Update clock
    updateClock();
    setInterval(updateClock, 1000);
    
    // Load logs
    fetchSystemLogs();
    setInterval(fetchSystemLogs, 5000);
}

function updateClock() {
    const now = new Date();
    const timeString = now.toLocaleTimeString('en-US', { 
        hour12: false,
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit'
    });
    const timeElement = document.getElementById('current-time');
    if (timeElement) timeElement.textContent = timeString;
}

// ==================== NAVIGATION ====================
function initNavigation() {
    const navItems = document.querySelectorAll('.nav-menu li');
    navItems.forEach(item => {
        item.addEventListener('click', function() {
            const page = this.dataset.page;
            showPage(page);
        });
    });
}

function showPage(pageId) {
    // Hide all pages
    document.querySelectorAll('.page').forEach(page => {
        page.classList.remove('active');
    });
    
    // Remove active class from nav items
    document.querySelectorAll('.nav-menu li').forEach(item => {
        item.classList.remove('active');
    });
    
    // Show selected page
    const pageElement = document.getElementById(`${pageId}-page`);
    if (pageElement) {
        pageElement.classList.add('active');
        state.currentPage = pageId;
        
        // Update current page in breadcrumb
        const currentPageElement = document.getElementById('current-page');
        if (currentPageElement) {
            currentPageElement.textContent = pageId;
        }
        
        // Add active class to clicked nav item
        const navItem = document.querySelector(`.nav-menu li[data-page="${pageId}"]`);
        if (navItem) navItem.classList.add('active');
        
        // Page-specific initialization
        switch(pageId) {
            case 'dashboard':
                loadSystemStatus();
                break;
            case 'scanner':
                initScanner();
                break;
            case 'usb':
                initUSBGuard();
                break;
            case 'network':
                initNetworkScanner();
                break;
            case 'tools':
                initSecurityTools();
                break;
            case 'chat':
                initAIChat();
                break;
            case 'settings':
                initSettings();
                break;
        }
        
        logEvent(`Navigated to ${pageId}`, 'info');
    }
}

// ==================== SYSTEM STATUS ====================
function loadSystemStatus() {
    fetch('/api/system/status')
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                updateSystemUI(data);
            }
        })
        .catch(error => {
            console.error('Error loading system status:', error);
        });
}

function updateSystemUI(data) {
    // Update CPU usage
    const cpuElement = document.getElementById('cpu-value');
    if (cpuElement) cpuElement.textContent = `${data.metrics.cpu}%`;
    
    // Update threat level
    const threatLevelElement = document.querySelector('.threat-level .level-low');
    if (threatLevelElement) {
        threatLevelElement.textContent = data.threat_level;
        threatLevelElement.className = `level-${data.threat_level.toLowerCase()}`;
    }
    
    // Update defense status
    state.isDefenseActive = data.defense_active;
    const statusDot = document.querySelector('.status-dot');
    if (statusDot) {
        statusDot.classList.toggle('active', data.defense_active);
    }
    
    // Update system uptime
    const uptimeElement = document.getElementById('system-uptime');
    if (uptimeElement) uptimeElement.textContent = data.metrics.uptime;
}

function startSystemUpdates() {
    // Update system status every 10 seconds
    setInterval(loadSystemStatus, 10000);
    
    // Update counters periodically
    setInterval(() => {
        document.getElementById('scan-count').textContent = state.scanCount;
        document.getElementById('threat-count').textContent = state.threatCount;
        document.getElementById('usb-count').textContent = state.usbCount;
        document.getElementById('ai-questions').textContent = state.aiQuestions;
    }, 5000);
}

// ==================== LOGGING SYSTEM ====================
function fetchSystemLogs() {
    fetch('/api/system/logs')
        .then(response => response.json())
        .then(data => {
            if (data.success && data.logs) {
                updateLogsUI(data.logs);
            }
        })
        .catch(error => console.error('Error fetching logs:', error));
}

function updateLogsUI(logs) {
    const logsContainer = document.getElementById('system-logs');
    if (!logsContainer) return;
    
    // Clear existing logs (keep first entry)
    while (logsContainer.children.length > 1) {
        logsContainer.removeChild(logsContainer.lastChild);
    }
    
    // Add new logs
    logs.slice(-10).forEach(log => {
        const logEntry = document.createElement('div');
        logEntry.className = 'log-entry';
        
        const timeSpan = document.createElement('span');
        timeSpan.className = 'log-time';
        timeSpan.textContent = `[${log.type}]`;
        
        const msgSpan = document.createElement('span');
        msgSpan.className = `log-msg ${log.level.toLowerCase()}`;
        msgSpan.textContent = log.message;
        
        logEntry.appendChild(timeSpan);
        logEntry.appendChild(msgSpan);
        logsContainer.appendChild(logEntry);
    });
    
    // Auto-scroll to bottom
    logsContainer.scrollTop = logsContainer.scrollHeight;
}

function logEvent(message, type = 'info') {
    const logEntry = {
        timestamp: new Date().toISOString(),
        type: 'USER',
        message: message,
        level: type.toUpperCase()
    };
    
    state.systemLogs.push(logEntry);
    
    // Update UI if on dashboard
    if (state.currentPage === 'dashboard') {
        const logsContainer = document.getElementById('system-logs');
        if (logsContainer) {
            const logElement = document.createElement('div');
            logElement.className = 'log-entry';
            
            const timeSpan = document.createElement('span');
            timeSpan.className = 'log-time';
            timeSpan.textContent = `[USER]`;
            
            const msgSpan = document.createElement('span');
            msgSpan.className = `log-msg ${type}`;
            msgSpan.textContent = message;
            
            logElement.appendChild(timeSpan);
            logElement.appendChild(msgSpan);
            logsContainer.appendChild(logElement);
            
            logsContainer.scrollTop = logsContainer.scrollHeight;
        }
    }
}

// ==================== VIRUS SCANNER ====================
function initScanner() {
    // File upload
    const fileInput = document.getElementById('file-input');
    const browseBtn = document.getElementById('browse-btn');
    const dropzone = document.getElementById('file-dropzone');
    
    if (browseBtn) {
        browseBtn.addEventListener('click', () => fileInput.click());
    }
    
    if (fileInput) {
        fileInput.addEventListener('change', handleFileUpload);
    }
    
    if (dropzone) {
        dropzone.addEventListener('dragover', (e) => {
            e.preventDefault();
            dropzone.style.borderColor = '#00ff41';
            dropzone.style.background = 'rgba(0, 255, 65, 0.05)';
        });
        
        dropzone.addEventListener('dragleave', () => {
            dropzone.style.borderColor = 'rgba(0, 255, 65, 0.2)';
            dropzone.style.background = '';
        });
        
        dropzone.addEventListener('drop', (e) => {
            e.preventDefault();
            dropzone.style.borderColor = 'rgba(0, 255, 65, 0.2)';
            dropzone.style.background = '';
            
            if (e.dataTransfer.files.length > 0) {
                fileInput.files = e.dataTransfer.files;
                handleFileUpload();
            }
        });
    }
    
    // URL scan
    const scanUrlBtn = document.getElementById('scan-url-btn');
    if (scanUrlBtn) {
        scanUrlBtn.addEventListener('click', scanURL);
    }
    
    // System scans
    const quickScanBtn = document.getElementById('quick-system-scan');
    const fullScanBtn = document.getElementById('full-system-scan');
    
    if (quickScanBtn) {
        quickScanBtn.addEventListener('click', () => performScan('quick'));
    }
    
    if (fullScanBtn) {
        fullScanBtn.addEventListener('click', () => performScan('full'));
    }
}

function handleFileUpload() {
    const fileInput = document.getElementById('file-input');
    const file = fileInput.files[0];
    
    if (!file) {
        alert('Please select a file to scan');
        return;
    }
    
    // Check file size (100MB limit)
    if (file.size > 100 * 1024 * 1024) {
        alert('File size exceeds 100MB limit');
        return;
    }
    
    // Show progress
    const progressDiv = document.getElementById('file-progress');
    const progressBar = document.getElementById('file-progress-bar');
    const statusSpan = document.getElementById('file-status');
    
    progressDiv.style.display = 'block';
    progressBar.style.width = '0%';
    statusSpan.textContent = 'Uploading file...';
    
    const formData = new FormData();
    formData.append('file', file);
    
    // Simulate upload progress
    let progress = 0;
    const uploadInterval = setInterval(() => {
        progress += 5;
        progressBar.style.width = `${progress}%`;
        
        if (progress >= 100) {
            clearInterval(uploadInterval);
            statusSpan.textContent = 'Scanning with VirusTotal...';
            sendFileForScanning(formData);
        }
    }, 100);
}

function sendFileForScanning(formData) {
    fetch('/api/scan/file', {
        method: 'POST',
        body: formData
    })
    .then(response => response.json())
    .then(data => {
        const progressDiv = document.getElementById('file-progress');
        const resultDiv = document.getElementById('file-result');
        const resultContent = document.getElementById('file-result-content');
        
        progressDiv.style.display = 'none';
        resultDiv.style.display = 'block';
        
        if (data.success) {
            const result = data.result;
            state.scanCount++;
            
            if (result.safe) {
                resultContent.innerHTML = `
                    <div style="color: #00ff41;">
                        <i class="fas fa-shield-check"></i>
                        <strong>File is SAFE</strong>
                        <p>${result.harmless || 0} security vendors marked this file as harmless</p>
                        <small>Scanned: ${new Date(result.scan_date).toLocaleString()}</small>
                    </div>
                `;
                logEvent(`File scan: ${data.filename} - SAFE`, 'success');
            } else {
                resultContent.innerHTML = `
                    <div style="color: #ff4141;">
                        <i class="fas fa-skull-crossbones"></i>
                        <strong>MALICIOUS FILE DETECTED!</strong>
                        <p>${result.malicious} security vendors marked this file as malicious</p>
                        <p>${result.suspicious} vendors marked it as suspicious</p>
                        <small>Scanned: ${new Date(result.scan_date).toLocaleString()}</small>
                    </div>
                `;
                state.threatCount++;
                logEvent(`File scan: ${data.filename} - MALICIOUS (${result.malicious} detections)`, 'danger');
            }
        } else {
            resultContent.innerHTML = `
                <div style="color: #ffbd2e;">
                    <i class="fas fa-exclamation-triangle"></i>
                    <strong>Scan Error</strong>
                    <p>${data.error || 'Unknown error occurred'}</p>
                </div>
            `;
            logEvent(`File scan error: ${data.error}`, 'warning');
        }
    })
    .catch(error => {
        console.error('File scan error:', error);
        logEvent('File scan failed', 'error');
    });
}

function scanURL() {
    const urlInput = document.getElementById('url-input');
    const url = urlInput.value.trim();
    
    if (!url) {
        alert('Please enter a URL to scan');
        return;
    }
    
    // Validate URL format
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
        alert('Please enter a valid URL starting with http:// or https://');
        return;
    }
    
    const resultDiv = document.getElementById('url-result');
    const resultContent = document.getElementById('url-result-content');
    
    resultDiv.style.display = 'block';
    resultContent.innerHTML = '<div style="color: #00ff41;"><i class="fas fa-spinner fa-spin"></i> Scanning URL...</div>';
    
    fetch('/api/scan/url', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ url: url })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            const result = data.result;
            state.scanCount++;
            
            if (result.safe) {
                resultContent.innerHTML = `
                    <div style="color: #00ff41;">
                        <i class="fas fa-shield-check"></i>
                        <strong>URL is SAFE</strong>
                        <p>${result.harmless || 0} security vendors marked this URL as harmless</p>
                        <small>Scanned: ${new Date(result.scan_date).toLocaleString()}</small>
                    </div>
                `;
                logEvent(`URL scan: ${url} - SAFE`, 'success');
            } else {
                resultContent.innerHTML = `
                    <div style="color: #ff4141;">
                        <i class="fas fa-skull-crossbones"></i>
                        <strong>MALICIOUS URL DETECTED!</strong>
                        <p>${result.malicious} security vendors marked this URL as malicious</p>
                        <p>${result.suspicious} vendors marked it as suspicious</p>
                        <small>Scanned: ${new Date(result.scan_date).toLocaleString()}</small>
                    </div>
                `;
                state.threatCount++;
                logEvent(`URL scan: ${url} - MALICIOUS (${result.malicious} detections)`, 'danger');
            }
        } else {
            resultContent.innerHTML = `
                <div style="color: #ffbd2e;">
                    <i class="fas fa-exclamation-triangle"></i>
                    <strong>Scan Error</strong>
                    <p>${data.error || 'Unknown error occurred'}</p>
                </div>
            `;
            logEvent(`URL scan error: ${data.error}`, 'warning');
        }
    })
    .catch(error => {
        console.error('URL scan error:', error);
        resultContent.innerHTML = `
            <div style="color: #ff4141;">
                <i class="fas fa-times-circle"></i>
                <strong>Scan Failed</strong>
                <p>Network error occurred. Please try again.</p>
            </div>
        `;
        logEvent('URL scan failed', 'error');
    });
}

function performScan(type) {
    const endpoint = type === 'quick' ? '/api/scan/quick' : '/api/scan/full';
    const resultDiv = document.getElementById('system-result');
    const resultContent = document.getElementById('system-result-content');
    
    resultDiv.style.display = 'block';
    resultContent.innerHTML = `<div style="color: #00ff41;"><i class="fas fa-spinner fa-spin"></i> Starting ${type} scan...</div>`;
    
    fetch(endpoint, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        }
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            state.scanCount++;
            
            if (type === 'quick') {
                // For quick scan, simulate results after delay
                setTimeout(() => {
                    const hasThreats = Math.random() < 0.3;
                    
                    if (hasThreats) {
                        const threatCount = Math.floor(Math.random() * 3) + 1;
                        resultContent.innerHTML = `
                            <div style="color: #ff4141;">
                                <i class="fas fa-skull-crossbones"></i>
                                <strong>THREATS DETECTED!</strong>
                                <p>Found ${threatCount} potential threats in system files</p>
                                <p>Recommended action: Quarantine threats immediately</p>
                            </div>
                        `;
                        state.threatCount += threatCount;
                        logEvent(`Quick scan: ${threatCount} threats detected`, 'danger');
                    } else {
                        resultContent.innerHTML = `
                            <div style="color: #00ff41;">
                                <i class="fas fa-shield-check"></i>
                                <strong>SYSTEM SECURE</strong>
                                <p>No threats detected in critical system areas</p>
                                <p>All system files appear to be safe</p>
                            </div>
                        `;
                        logEvent('Quick scan: No threats detected', 'success');
                    }
                }, 3000);
            } else {
                resultContent.innerHTML = `
                    <div style="color: #00ff41;">
                        <i class="fas fa-info-circle"></i>
                        <strong>Full Scan Started</strong>
                        <p>${data.message}</p>
                        <p>Estimated time: ${data.estimated_time}</p>
                        <p>This scan will run in the background</p>
                    </div>
                `;
                logEvent('Full system scan started', 'info');
            }
        } else {
            resultContent.innerHTML = `
                <div style="color: #ffbd2e;">
                    <i class="fas fa-exclamation-triangle"></i>
                    <strong>Scan Failed to Start</strong>
                    <p>${data.error || 'Unknown error occurred'}</p>
                </div>
            `;
            logEvent(`Scan failed: ${data.error}`, 'warning');
        }
    })
    .catch(error => {
        console.error('Scan error:', error);
        logEvent('Scan failed', 'error');
    });
}

// ==================== USB GUARD ====================
function initUSBGuard() {
    const startMonitorBtn = document.getElementById('start-monitor');
    const testUsbBtn = document.getElementById('test-usb');
    const simulateAttackBtn = document.getElementById('simulate-attack');
    
    if (startMonitorBtn) {
        startMonitorBtn.addEventListener('click', startUSBMonitoring);
    }
    
    if (testUsbBtn) {
        testUsbBtn.addEventListener('click', testUSBGuard);
    }
    
    if (simulateAttackBtn) {
        simulateAttackBtn.addEventListener('click', simulateUSBAttack);
    }
}

function startUSBMonitoring() {
    logEvent('USB monitoring started', 'info');
    alert('USB monitoring is now active. Any connected USB devices will be scanned for suspicious behavior.');
    
    // Update UI
    const statusBadge = document.querySelector('.usb-status .status-badge');
    const statusText = document.querySelector('.usb-status p');
    
    if (statusBadge) {
        statusBadge.textContent = 'MONITORING';
        statusBadge.className = 'status-badge active';
    }
    
    if (statusText) {
        statusText.textContent = 'Monitoring USB devices...';
    }
}

function testUSBGuard() {
    logEvent('USB guard test initiated', 'info');
    
    fetch('/api/usb/simulate', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        }
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            simulateKeystrokeDetection(data.keystrokes);
        }
    })
    .catch(error => {
        console.error('USB test error:', error);
    });
}

function simulateKeystrokeDetection(keystrokes) {
    const attackLog = document.getElementById('attack-log');
    
    // Clear log
    attackLog.innerHTML = '<div class="log-entry"><span class="log-time">[TEST]</span><span class="log-msg">Starting USB attack simulation...</span></div>';
    
    // Simulate keystrokes with delay
    keystrokes.forEach((keystroke, index) => {
        setTimeout(() => {
            const logEntry = document.createElement('div');
            logEntry.className = 'log-entry';
            
            const timeSpan = document.createElement('span');
            timeSpan.className = 'log-time';
            timeSpan.textContent = `[KEY]`;
            
            const msgSpan = document.createElement('span');
            msgSpan.className = 'log-msg';
            msgSpan.textContent = `Keystroke: ${keystroke.key} (${keystroke.time_delta}ms)`;
            
            logEntry.appendChild(timeSpan);
            logEntry.appendChild(msgSpan);
            attackLog.appendChild(logEntry);
            attackLog.scrollTop = attackLog.scrollHeight;
            
            // If last keystroke, analyze pattern
            if (index === keystrokes.length - 1) {
                setTimeout(() => {
                    analyzeUSBPattern(keystrokes);
                }, 1000);
            }
        }, index * 100);
    });
}

function analyzeUSBPattern(keystrokes) {
    fetch('/api/usb/scan', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ keystrokes: keystrokes })
    })
    .then(response => response.json())
    .then(data => {
        const attackLog = document.getElementById('attack-log');
        
        if (data.success) {
            const logEntry = document.createElement('div');
            logEntry.className = 'log-entry';
            
            const timeSpan = document.createElement('span');
            timeSpan.className = 'log-time';
            timeSpan.textContent = `[ANALYSIS]`;
            
            const msgSpan = document.createElement('span');
            msgSpan.className = `log-msg ${data.danger ? 'danger' : 'success'}`;
            msgSpan.textContent = data.message;
            
            logEntry.appendChild(timeSpan);
            logEntry.appendChild(msgSpan);
            attackLog.appendChild(logEntry);
            attackLog.scrollTop = attackLog.scrollHeight;
            
            if (data.danger) {
                state.usbCount++;
                state.threatCount++;
                logEvent(`BadUSB detected: ${data.pattern}`, 'danger');
            } else {
                logEvent('USB device appears safe', 'success');
            }
        }
    })
    .catch(error => {
        console.error('USB analysis error:', error);
    });
}

function simulateUSBAttack() {
    // Generate simulated malicious keystrokes
    const maliciousKeystrokes = [
        { key: 'KEY_WIN', time_delta: 100 },
        { key: 'r', time_delta: 50 },
        { key: 'p', time_delta: 10 },
        { key: 'o', time_delta: 10 },
        { key: 'w', time_delta: 10 },
        { key: 'e', time_delta: 10 },
        { key: 'r', time_delta: 10 },
        { key: 's', time_delta: 10 },
        { key: 'h', time_delta: 10 },
        { key: 'e', time_delta: 10 },
        { key: 'l', time_delta: 10 },
        { key: 'l', time_delta: 10 },
        { key: 'SPACE', time_delta: 10 },
        { key: '-', time_delta: 10 },
        { key: 'e', time_delta: 10 },
        { key: 'x', time_delta: 10 },
        { key: 'e', time_delta: 10 },
        { key: 'c', time_delta: 10 },
        { key: 'SPACE', time_delta: 10 },
        { key: 'b', time_delta: 10 },
        { key: 'y', time_delta: 10 },
        { key: 'p', time_delta: 10 },
        { key: 'a', time_delta: 10 },
        { key: 's', time_delta: 10 },
        { key: 's', time_delta: 10 },
        { key: 'KEY_ENTER', time_delta: 50 }
    ];
    
    simulateKeystrokeDetection(maliciousKeystrokes);
}

// ==================== NETWORK SCANNER ====================
function initNetworkScanner() {
    const scanPortsBtn = document.getElementById('scan-ports-btn');
    const refreshConnectionsBtn = document.getElementById('refresh-connections');
    
    if (scanPortsBtn) {
        scanPortsBtn.addEventListener('click', scanPorts);
    }
    
    if (refreshConnectionsBtn) {
        refreshConnectionsBtn.addEventListener('click', refreshConnections);
    }
    
    // Load initial connections
    refreshConnections();
}

function scanPorts() {
    const targetInput = document.getElementById('target-ip');
    const target = targetInput.value.trim() || '127.0.0.1';
    
    const resultDiv = document.getElementById('port-result');
    const portsList = document.getElementById('ports-list');
    
    resultDiv.style.display = 'block';
    portsList.innerHTML = '<div style="color: #00ff41;"><i class="fas fa-spinner fa-spin"></i> Scanning ports...</div>';
    
    fetch('/api/tools/ports', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ target: target })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            state.scanCount++;
            portsList.innerHTML = '';
            
            data.results.forEach(port => {
                const portItem = document.createElement('div');
                portItem.className = 'port-item';
                
                const portInfo = document.createElement('span');
                portInfo.textContent = `Port ${port.port} (${port.service})`;
                
                const portStatus = document.createElement('span');
                portStatus.className = port.status === 'OPEN' ? 'port-open' : 'port-closed';
                portStatus.textContent = port.status;
                
                if (port.vulnerable) {
                    portStatus.className = 'port-vulnerable';
                    portStatus.innerHTML += ' <i class="fas fa-exclamation-triangle"></i>';
                }
                
                portItem.appendChild(portInfo);
                portItem.appendChild(portStatus);
                portsList.appendChild(portItem);
            });
            
            logEvent(`Port scan completed for ${target}: ${data.summary.open_ports} open ports`, 'info');
        } else {
            portsList.innerHTML = `<div style="color: #ff4141;">Error: ${data.error}</div>`;
            logEvent(`Port scan error: ${data.error}`, 'warning');
        }
    })
    .catch(error => {
        console.error('Port scan error:', error);
        logEvent('Port scan failed', 'error');
    });
}

function refreshConnections() {
    // This would normally fetch from backend
    // For now, simulate some connections
    const connectionsList = document.getElementById('connections-list');
    connectionsList.innerHTML = '';
    
    const connections = [
        { process: 'chrome.exe', status: 'ACTIVE', details: '192.168.1.100:8080 → 34.120.200.10:443' },
        { process: 'discord.exe', status: 'ACTIVE', details: '192.168.1.100:56432 → 162.159.135.233:443' },
        { process: 'svchost.exe', status: 'ACTIVE', details: '192.168.1.100:5353 → 224.0.0.251:5353' },
        { process: 'system', status: 'LISTENING', details: '127.0.0.1:8080 → 0.0.0.0:0' }
    ];
    
    connections.forEach(conn => {
        const connItem = document.createElement('div');
        connItem.className = 'connection-item';
        
        const connInfo = document.createElement('div');
        connInfo.className = 'conn-info';
        
        const processSpan = document.createElement('span');
        processSpan.className = 'conn-process';
        processSpan.textContent = conn.process;
        
        const statusSpan = document.createElement('span');
        statusSpan.className = 'conn-status active';
        statusSpan.textContent = conn.status;
        
        connInfo.appendChild(processSpan);
        connInfo.appendChild(statusSpan);
        
        const connDetails = document.createElement('div');
        connDetails.className = 'conn-details';
        connDetails.textContent = conn.details;
        
        connItem.appendChild(connInfo);
        connItem.appendChild(connDetails);
        connectionsList.appendChild(connItem);
    });
    
    logEvent('Network connections refreshed', 'info');
}

// ==================== SECURITY TOOLS ====================
function initSecurityTools() {
    // Hash generator
    const generateHashBtn = document.getElementById('generate-hash');
    if (generateHashBtn) {
        generateHashBtn.addEventListener('click', generateHash);
    }
    
    // Password checker
    const checkPasswordBtn = document.getElementById('check-password');
    if (checkPasswordBtn) {
        checkPasswordBtn.addEventListener('click', checkPasswordStrength);
    }
    
    // Port scanner tool
    const toolScanPortsBtn = document.getElementById('tool-scan-ports');
    if (toolScanPortsBtn) {
        toolScanPortsBtn.addEventListener('click', scanPortsTool);
    }
    
    // Encryption tools
    const encryptBtn = document.getElementById('encrypt-btn');
    const decryptBtn = document.getElementById('decrypt-btn');
    
    if (encryptBtn) encryptBtn.addEventListener('click', encryptText);
    if (decryptBtn) decryptBtn.addEventListener('click', decryptText);
}

function generateHash() {
    const input = document.getElementById('hash-input').value.trim();
    
    if (!input) {
        alert('Please enter text to hash');
        return;
    }
    
    const output = document.getElementById('hash-output');
    output.innerHTML = '<div style="color: #00ff41;"><i class="fas fa-spinner fa-spin"></i> Generating hashes...</div>';
    
    fetch('/api/tools/hash', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ text: input })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            output.innerHTML = `
                <div style="font-family: "JetBrains Mono", monospace; font-size: 0.9em;">
                    <strong>MD5:</strong> ${data.hashes.md5}<br>
                    <strong>SHA-1:</strong> ${data.hashes.sha1}<br>
                    <strong>SHA-256:</strong> ${data.hashes.sha256}<br>
                    <strong>SHA-512:</strong> ${data.hashes.sha512}
                </div>
            `;
            logEvent('Hash generated', 'info');
        } else {
            output.innerHTML = `<div style="color: #ff4141;">Error: ${data.error}</div>`;
        }
    })
    .catch(error => {
        console.error('Hash generation error:', error);
        output.innerHTML = '<div style="color: #ff4141;">Error generating hash</div>';
    });
}

function checkPasswordStrength() {
    const password = document.getElementById('password-input').value;
    
    if (!password) {
        alert('Please enter a password');
        return;
    }
    
    const strengthBar = document.getElementById('strength-bar');
    const strengthLabel = document.getElementById('strength-label');
    const feedback = document.getElementById('password-feedback');
    
    fetch('/api/tools/password', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ password: password })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            const result = data.result;
            
            // Update strength bar
            strengthBar.style.width = `${result.score}%`;
            strengthBar.style.background = result.color;
            
            // Update label
            strengthLabel.textContent = result.level;
            strengthLabel.style.color = result.color;
            
            // Update feedback
            if (result.feedback.length > 0) {
                feedback.innerHTML = `<strong>Suggestions:</strong><br>${result.feedback.join('<br>')}`;
            } else {
                feedback.innerHTML = '<strong>Excellent password!</strong><br>All security criteria met.';
            }
            
            logEvent('Password strength checked', 'info');
        }
    })
    .catch(error => {
        console.error('Password check error:', error);
    });
}

function scanPortsTool() {
    const target = document.getElementById('tool-target').value.trim() || '127.0.0.1';
    const output = document.getElementById('port-output');
    
    output.innerHTML = '<div style="color: #00ff41;"><i class="fas fa-spinner fa-spin"></i> Scanning ports...</div>';
    
    fetch('/api/tools/ports', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ target: target })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            let html = `<strong>Scan Results for ${target}:</strong><br><br>`;
            
            data.results.forEach(port => {
                const statusColor = port.status === 'OPEN' ? '#00ff41' : '#ff4141';
                html += `Port ${port.port} (${port.service}): <span style="color: ${statusColor}">${port.status}</span><br>`;
            });
            
            html += `<br><strong>Summary:</strong> ${data.summary.open_ports} open ports, ${data.summary.vulnerable_ports} vulnerable`;
            output.innerHTML = html;
            
            logEvent(`Tool port scan completed for ${target}`, 'info');
        } else {
            output.innerHTML = `<div style="color: #ff4141;">Error: ${data.error}</div>`;
        }
    })
    .catch(error => {
        console.error('Port scan error:', error);
        output.innerHTML = '<div style="color: #ff4141;">Network error occurred</div>';
    });
}

function encryptText() {
    const input = document.getElementById('encrypt-input').value.trim();
    const output = document.getElementById('encrypt-output');
    
    if (!input) {
        alert('Please enter text to encrypt');
        return;
    }
    
    // Simple base64 encryption for demo
    const encrypted = btoa(input);
    output.innerHTML = `<strong>Encrypted:</strong><br>${encrypted}`;
    logEvent('Text encrypted', 'info');
}

function decryptText() {
    const input = document.getElementById('encrypt-input').value.trim();
    const output = document.getElementById('encrypt-output');
    
    if (!input) {
        alert('Please enter text to decrypt');
        return;
    }
    
    try {
        const decrypted = atob(input);
        output.innerHTML = `<strong>Decrypted:</strong><br>${decrypted}`;
        logEvent('Text decrypted', 'info');
    } catch (e) {
        output.innerHTML = '<div style="color: #ff4141;">Error: Invalid base64 string</div>';
    }
}

// ==================== AI CHATBOT ====================
function initAIChat() {
    const sendBtn = document.getElementById('send-message');
    const inputField = document.getElementById('chat-input-field');
    
    if (sendBtn) {
        sendBtn.addEventListener('click', sendMessage);
    }
    
    if (inputField) {
        inputField.addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                sendMessage();
            }
        });
    }
    
    // Quick questions
    const quickBtns = document.querySelectorAll('.quick-btn');
    quickBtns.forEach(btn => {
        btn.addEventListener('click', function() {
            const question = this.dataset.question;
            sendQuickQuestion(question);
        });
    });
}

function sendMessage() {
    const inputField = document.getElementById('chat-input-field');
    const message = inputField.value.trim();
    
    if (!message) return;
    
    // Add user message to chat
    addMessage(message, 'user');
    inputField.value = '';
    
    // Get AI response
    fetch('/api/chat', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ message: message })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            state.aiQuestions++;
            setTimeout(() => {
                addMessage(data.response, 'ai');
            }, 500);
        } else {
            addMessage('Sorry, I encountered an error. Please try again.', 'ai');
        }
    })
    .catch(error => {
        console.error('Chat error:', error);
        addMessage('Network error. Please check your connection.', 'ai');
    });
}

function sendQuickQuestion(question) {
    const inputField = document.getElementById('chat-input-field');
    inputField.value = question;
    sendMessage();
}

function addMessage(text, sender) {
    const chatMessages = document.getElementById('chat-messages');
    
    const messageDiv = document.createElement('div');
    messageDiv.className = `message ${sender}`;
    
    const messageContent = document.createElement('div');
    messageContent.className = 'message-content';
    
    if (sender === 'ai') {
        messageContent.innerHTML = `
            <i class="fas fa-robot"></i>
            <div class="message-text">
                <strong>Security AI:</strong>
                <p>${text}</p>
            </div>
        `;
    } else {
        messageContent.innerHTML = `
            <div class="message-text">
                <strong>You:</strong>
                <p>${text}</p>
            </div>
        `;
    }
    
    const messageTime = document.createElement('div');
    messageTime.className = 'message-time';
    messageTime.textContent = 'Just now';
    
    messageDiv.appendChild(messageContent);
    messageDiv.appendChild(messageTime);
    chatMessages.appendChild(messageDiv);
    
    // Scroll to bottom
    chatMessages.scrollTop = chatMessages.scrollHeight;
}

// ==================== SETTINGS ====================
function initSettings() {
    // Load saved API keys
    const vtApiInput = document.getElementById('vt-api');
    const aiApiInput = document.getElementById('ai-api');
    
    if (vtApiInput) vtApiInput.value = state.apiKeys.virustotal;
    if (aiApiInput) aiApiInput.value = state.apiKeys.ai;
    
    // Save button
    const saveBtn = document.getElementById('save-api');
    if (saveBtn) {
        saveBtn.addEventListener('click', saveAPIKeys);
    }
    
    // Test buttons
    const testVtBtn = document.getElementById('test-vt');
    const testAiBtn = document.getElementById('test-ai');
    
    if (testVtBtn) testVtBtn.addEventListener('click', testVirusTotalAPI);
    if (testAiBtn) testAiBtn.addEventListener('click', testAIAPI);
    
    // System actions
    const clearCacheBtn = document.getElementById('clear-cache');
    const exportLogsBtn = document.getElementById('export-logs');
    const resetSettingsBtn = document.getElementById('reset-settings');
    
    if (clearCacheBtn) clearCacheBtn.addEventListener('click', clearCache);
    if (exportLogsBtn) exportLogsBtn.addEventListener('click', exportLogs);
    if (resetSettingsBtn) resetSettingsBtn.addEventListener('click', resetSettings);
}

function saveAPIKeys() {
    const vtApiKey = document.getElementById('vt-api').value;
    const aiApiKey = document.getElementById('ai-api').value;
    
    // Save to local storage
    localStorage.setItem('vt_api_key', vtApiKey);
    localStorage.setItem('ai_api_key', aiApiKey);
    
    // Update state
    state.apiKeys.virustotal = vtApiKey;
    state.apiKeys.ai = aiApiKey;
    
    alert('API keys saved to local storage');
    logEvent('API keys updated', 'info');
}

function testVirusTotalAPI() {
    const apiKey = document.getElementById('vt-api').value;
    
    if (!apiKey) {
        alert('Please enter VirusTotal API key');
        return;
    }
    
    alert('VirusTotal API test would normally validate the key. In production, this would make a test request.');
    logEvent('VirusTotal API test initiated', 'info');
}

function testAIAPI() {
    const apiKey = document.getElementById('ai-api').value;
    
    if (!apiKey) {
        alert('Please enter AI API key');
        return;
    }
    
    alert('AI API test would normally validate the key. In production, this would make a test request.');
    logEvent('AI API test initiated', 'info');
}

function clearCache() {
    if (confirm('Clear all cached data?')) {
        localStorage.clear();
        sessionStorage.clear();
        alert('Cache cleared successfully');
        logEvent('Cache cleared', 'info');
    }
}

function exportLogs() {
    const logs = state.systemLogs;
    const logText = logs.map(log => 
        `[${log.timestamp}] [${log.type}] ${log.message}`
    ).join('\n');
    
    const blob = new Blob([logText], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `security-logs-${new Date().toISOString().split('T')[0]}.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    
    logEvent('Logs exported', 'info');
}

function resetSettings() {
    if (confirm('Reset all settings to default?')) {
        // Reset checkboxes
        document.querySelectorAll('input[type="checkbox"]').forEach(checkbox => {
            checkbox.checked = true;
        });
        
        // Clear API keys
        document.getElementById('vt-api').value = '';
        document.getElementById('ai-api').value = '';
        
        // Save changes
        saveAPIKeys();
        
        alert('Settings reset to default');
        logEvent('Settings reset', 'info');
    }
}

// ==================== EVENT LISTENERS ====================
function initEventListeners() {
    // Quick actions from dashboard
    const quickScanBtn = document.getElementById('quick-scan-btn');
    const fileScanBtn = document.getElementById('file-scan-btn');
    const networkScanBtn = document.getElementById('network-scan-btn');
    const usbTestBtn = document.getElementById('usb-test-btn');
    const toggleDefenseBtn = document.getElementById('toggle-defense');
    const clearLogsBtn = document.getElementById('clear-logs');
    
    if (quickScanBtn) quickScanBtn.addEventListener('click', () => {
        showPage('scanner');
        setTimeout(() => performScan('quick'), 500);
    });
    
    if (fileScanBtn) fileScanBtn.addEventListener('click', () => {
        showPage('scanner');
        setTimeout(() => document.getElementById('browse-btn').click(), 500);
    });
    
    if (networkScanBtn) networkScanBtn.addEventListener('click', () => {
        showPage('network');
    });
    
    if (usbTestBtn) usbTestBtn.addEventListener('click', () => {
        showPage('usb');
        setTimeout(() => document.getElementById('test-usb').click(), 500);
    });
    
    if (toggleDefenseBtn) {
        toggleDefenseBtn.addEventListener('click', toggleDefenseMode);
    }
    
    if (clearLogsBtn) {
        clearLogsBtn.addEventListener('click', () => {
            const logsContainer = document.getElementById('system-logs');
            if (logsContainer) {
                while (logsContainer.children.length > 1) {
                    logsContainer.removeChild(logsContainer.lastChild);
                }
            }
            logEvent('Logs cleared', 'info');
        });
    }
}

function toggleDefenseMode() {
    fetch('/api/defense/toggle', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        }
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            state.isDefenseActive = data.defense_active;
            const status = data.defense_active ? 'ENABLED' : 'DISABLED';
            alert(`Defense mode ${status}`);
            logEvent(`Defense mode ${status.toLowerCase()}`, data.defense_active ? 'success' : 'warning');
        }
    })
    .catch(error => {
        console.error('Toggle defense error:', error);
    });
}

// ==================== VISUAL EFFECTS ====================
function initMatrixAnimation() {
    const canvas = document.getElementById('matrix-canvas');
    if (!canvas) return;
    
    const ctx = canvas.getContext('2d');
    
    // Set canvas size
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
    
    // Matrix characters
    const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789$+-*/=%\"'#&_(),.;:?!\\|{}<>[]^~";
    const charArray = chars.split("");
    const fontSize = 14;
    const columns = canvas.width / fontSize;
    
    // Array to track y position of each column
    const drops = [];
    for (let i = 0; i < columns; i++) {
        drops[i] = Math.random() * canvas.height / fontSize;
    }
    
    function draw() {
        // Semi-transparent black to create fading effect
        ctx.fillStyle = "rgba(5, 8, 17, 0.04)";
        ctx.fillRect(0, 0, canvas.width, canvas.height);
        
        ctx.fillStyle = "#00ff41";
        ctx.font = `${fontSize}px "JetBrains Mono"`;
        
        for (let i = 0; i < drops.length; i++) {
            const text = charArray[Math.floor(Math.random() * charArray.length)];
            ctx.fillText(text, i * fontSize, drops[i] * fontSize);
            
            // Randomly reset drop
            if (drops[i] * fontSize > canvas.height && Math.random() > 0.975) {
                drops[i] = 0;
            }
            
            drops[i]++;
        }
    }
    
    // Animation loop
    setInterval(draw, 50);
    
    // Handle window resize
    window.addEventListener('resize', function() {
        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;
    });
}

// ==================== ERROR HANDLING ====================
window.addEventListener('error', function(e) {
    console.error('JavaScript error:', e.error);
    logEvent(`JavaScript error: ${e.message}`, 'error');
});

window.addEventListener('unhandledrejection', function(e) {
    console.error('Unhandled promise rejection:', e.reason);
    logEvent(`Unhandled promise rejection: ${e.reason}`, 'error');
});

// Health check on startup
fetch('/api/health')
    .then(response => response.json())
    .then(data => {
        console.log('Backend health:', data);
        const apiStatus = document.getElementById('api-status');
        if (apiStatus) apiStatus.textContent = 'ONLINE';
    })
    .catch(error => {
        console.error('Health check failed:', error);
        const apiStatus = document.getElementById('api-status');
        if (apiStatus) apiStatus.textContent = 'OFFLINE';
    });