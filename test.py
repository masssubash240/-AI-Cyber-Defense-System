import os
import time
import json
import base64
import hashlib
import socket
import random
import concurrent.futures
import subprocess
import platform
from threading import Lock
from collections import deque
from urllib.parse import urlparse
import requests
import psutil
from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from cryptography.fernet import Fernet
from dotenv import load_dotenv
from groq import Groq

# -------------------- Environment --------------------
load_dotenv()
VT_API_KEY = os.getenv('VT_API_KEY')
GROQ_API_KEY = os.getenv('GROQ_API_KEY')
AI_PROVIDER = os.getenv('AI_PROVIDER', 'groq').lower()
ENCRYPTION_KEY = os.getenv('ENCRYPTION_KEY')

# Check VirusTotal key
if not VT_API_KEY:
    print("⚠️  WARNING: VT_API_KEY not found. VirusTotal scans will use mock data.")
else:
    print("✅ VT_API_KEY loaded.")

# Check Groq key
if AI_PROVIDER == 'groq' and not GROQ_API_KEY:
    print("⚠️  GROQ_API_KEY missing. AI will use enhanced mock mode.")
    AI_PROVIDER = 'mock'
else:
    print("✅ GROQ_API_KEY loaded.")

# Encryption key
if not ENCRYPTION_KEY:
    ENCRYPTION_KEY = Fernet.generate_key().decode()
    print("⚠️  ENCRYPTION_KEY generated (temporary).")

cipher = Fernet(ENCRYPTION_KEY.encode() if isinstance(ENCRYPTION_KEY, str) else ENCRYPTION_KEY)

# -------------------- Logging --------------------
MAX_LOGS = 100
logs = deque(maxlen=MAX_LOGS)
log_lock = Lock()

def add_log(level, message):
    with log_lock:
        logs.appendleft({'time': time.strftime('%Y-%m-%d %H:%M:%S'), 'level': level, 'message': message})

# -------------------- Flask App --------------------
app = Flask(__name__, template_folder='templates', static_folder='static')
CORS(app)

# -------------------- Utility --------------------
def get_system_stats():
    cpu = psutil.cpu_percent(interval=0.5)
    memory = psutil.virtual_memory().percent
    uptime_seconds = int(time.time() - psutil.boot_time())
    h = uptime_seconds // 3600
    m = (uptime_seconds % 3600) // 60
    s = uptime_seconds % 60
    return {'cpu': cpu, 'memory': memory, 'uptime': f"{h:02d}:{m:02d}:{s:02d}"}

# -------------------- VirusTotal --------------------
def scan_file_vt(file_content, filename):
    if not VT_API_KEY:
        return {'malicious': 0, 'suspicious': 0, 'harmless': 65, 'undetected': 35}
    headers = {'x-apikey': VT_API_KEY}
    files = {'file': (filename, file_content)}
    try:
        upload_url = 'https://www.virustotal.com/api/v3/files'
        resp = requests.post(upload_url, headers=headers, files=files, timeout=30)
        resp.raise_for_status()
        analysis_id = resp.json()['data']['id']
        time.sleep(15)
        report_url = f'https://www.virustotal.com/api/v3/analyses/{analysis_id}'
        report = requests.get(report_url, headers=headers, timeout=30)
        report.raise_for_status()
        stats = report.json()['data']['attributes']['stats']
        add_log('INFO', f'File scan: {stats}')
        return stats
    except Exception as e:
        return {'error': str(e)}

def scan_url_vt(url):
    if not VT_API_KEY:
        return {'malicious': 0, 'suspicious': 0, 'harmless': 80, 'undetected': 20}
    headers = {'x-apikey': VT_API_KEY}
    try:
        submit_url = 'https://www.virustotal.com/api/v3/urls'
        resp = requests.post(submit_url, headers=headers, data={'url': url}, timeout=30)
        resp.raise_for_status()
        analysis_id = resp.json()['data']['id']
        time.sleep(5)
        report_url = f'https://www.virustotal.com/api/v3/analyses/{analysis_id}'
        report = requests.get(report_url, headers=headers, timeout=30)
        report.raise_for_status()
        stats = report.json()['data']['attributes']['stats']
        add_log('INFO', f'URL scan: {stats}')
        return stats
    except Exception as e:
        return {'error': str(e)}

# -------------------- Port Scanner --------------------
COMMON_PORTS = [21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080]

def scan_port(host, port, timeout=1.0):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return port, result == 0
    except:
        return port, False

def scan_ports(host, ports):
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        futures = {executor.submit(scan_port, host, p): p for p in ports}
        for future in concurrent.futures.as_completed(futures):
            port, is_open = future.result()
            if is_open:
                open_ports.append(port)
    return sorted(open_ports)

# -------------------- Web Scanner --------------------
def check_ssl(hostname):
    try:
        import ssl
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
            s.connect((hostname, 443))
        return {'valid': True}
    except:
        return {'valid': False}

def check_directory(url, path):
    try:
        full = url.rstrip('/') + '/' + path.lstrip('/')
        resp = requests.get(full, timeout=5, allow_redirects=False)
        return {'path': path, 'accessible': resp.status_code < 400}
    except:
        return {'path': path, 'accessible': False}

def check_xss(url):
    try:
        resp = requests.get(url, timeout=5)
        if '<form' in resp.text and 'csrf' not in resp.text.lower():
            return {'vulnerable': True, 'message': 'Forms without CSRF'}
        return {'vulnerable': False}
    except:
        return {'vulnerable': False}

def check_sqli(url):
    try:
        resp = requests.get(url, timeout=5)
        errors = ['sql', 'mysql', 'syntax error']
        if any(e in resp.text.lower() for e in errors):
            return {'vulnerable': True, 'message': 'SQL error pattern'}
        return {'vulnerable': False}
    except:
        return {'vulnerable': False}

# -------------------- SYSTEM CONTROL COMMANDS --------------------
def execute_system_command(cmd):
    """Execute system commands safely (simulated mode for demo)"""
    try:
        if platform.system() == 'Windows':
            if cmd == 'lock':
                # subprocess.run(['rundll32.exe', 'user32.dll,LockWorkStation'])
                return True, "🔒 Computer locked (simulated)"
            elif cmd == 'shutdown':
                # subprocess.run(['shutdown', '/s', '/t', '60'])
                return True, "⚠️ System shutdown initiated in 60 seconds (simulated)"
            elif cmd == 'restart':
                # subprocess.run(['shutdown', '/r', '/t', '60'])
                return True, "🔄 System restart initiated in 60 seconds (simulated)"
            elif cmd == 'firewall_on':
                # subprocess.run(['netsh', 'advfirewall', 'set', 'allprofiles', 'state', 'on'])
                return True, "🔥 Firewall enabled (simulated)"
            elif cmd == 'firewall_off':
                # subprocess.run(['netsh', 'advfirewall', 'set', 'allprofiles', 'state', 'off'])
                return True, "⚠️ Firewall disabled (simulated)"
            elif cmd == 'quick_scan':
                return True, "🛡️ Quick scan started... Scanning critical areas..."
            elif cmd == 'deep_scan':
                return True, "🔍 Deep scan started... Full system analysis in progress..."
            elif cmd == 'malware_scan':
                return True, "🦠 Malware scan initiated... Checking for threats..."
            elif cmd == 'check_processes':
                processes = []
                for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
                    try:
                        processes.append({
                            'pid': proc.info['pid'],
                            'name': proc.info['name'],
                            'cpu': proc.info['cpu_percent'],
                            'memory': proc.info['memory_percent']
                        })
                    except:
                        pass
                suspicious = [p for p in processes if p['cpu'] and p['cpu'] > 90]
                if suspicious:
                    return True, f"⚠️ Found {len(suspicious)} high-CPU processes: {[p['name'] for p in suspicious[:3]]}"
                return True, f"✅ All {len(processes)} processes running normally"
            elif cmd == 'kill_malware':
                return True, "🔪 Terminating suspicious processes... (simulated)"
            elif cmd == 'block_usb':
                return True, "🚫 Unknown USB devices blocked (simulated)"
            elif cmd == 'usb_status':
                return True, "🔌 USB Status: 2 devices connected, 0 threats detected"
            elif cmd == 'security_status':
                return True, "🛡️ Security Status: All systems operational. Threat level: LOW"
            elif cmd == 'system_lockdown':
                return True, "🔐 SYSTEM LOCKDOWN: All external access blocked, firewall max, USB disabled (simulated)"
        else:  # Linux/Mac
            if cmd == 'lock':
                return True, "🔒 Screen locked (simulated)"
            elif cmd == 'shutdown':
                return True, "⚠️ Shutdown initiated (simulated)"
            elif cmd == 'restart':
                return True, "🔄 Restart initiated (simulated)"
            elif cmd == 'firewall_on':
                return True, "🔥 Firewall enabled (simulated)"
            elif cmd == 'firewall_off':
                return True, "⚠️ Firewall disabled (simulated)"
            elif cmd == 'quick_scan':
                return True, "🛡️ Quick scan started..."
            elif cmd == 'deep_scan':
                return True, "🔍 Deep scan started..."
            elif cmd == 'malware_scan':
                return True, "🦠 Malware scan initiated..."
            elif cmd == 'check_processes':
                return True, f"✅ All processes running normally"
            elif cmd == 'kill_malware':
                return True, "🔪 Threats terminated (simulated)"
            elif cmd == 'block_usb':
                return True, "🚫 USB blocked (simulated)"
            elif cmd == 'usb_status':
                return True, "🔌 USB: 2 devices, 0 threats"
            elif cmd == 'security_status':
                return True, "🛡️ Security: All systems operational"
            elif cmd == 'system_lockdown':
                return True, "🔐 SYSTEM LOCKDOWN activated (simulated)"
        return False, "❌ Command not supported on this system"
    except Exception as e:
        return False, f"❌ Error: {str(e)}"

# Voice command parser
def parse_voice_command(text):
    """Convert voice text to system command"""
    t = text.lower().strip()
    
    # Lock commands
    if any(x in t for x in ['lock computer', 'lock system', 'lock my pc', 'lock']):
        return 'lock'
    # Shutdown commands
    if any(x in t for x in ['shutdown', 'shut down', 'turn off', 'power off']):
        return 'shutdown'
    # Restart commands
    if any(x in t for x in ['restart', 'reboot', 'start again']):
        return 'restart'
    # Firewall commands
    if 'firewall on' in t or 'enable firewall' in t or 'turn on firewall' in t:
        return 'firewall_on'
    if 'firewall off' in t or 'disable firewall' in t or 'turn off firewall' in t:
        return 'firewall_off'
    # Scan commands
    if 'quick scan' in t or 'fast scan' in t:
        return 'quick_scan'
    if 'deep scan' in t or 'full scan' in t or 'complete scan' in t:
        return 'deep_scan'
    if 'malware scan' in t or 'virus scan' in t or 'threat scan' in t:
        return 'malware_scan'
    # Process commands
    if 'check processes' in t or 'show processes' in t or 'running processes' in t:
        return 'check_processes'
    if 'kill malware' in t or 'stop malware' in t or 'terminate threat' in t:
        return 'kill_malware'
    # USB commands
    if 'block usb' in t or 'disable usb' in t or 'stop usb' in t:
        return 'block_usb'
    if 'usb status' in t or 'check usb' in t or 'usb devices' in t:
        return 'usb_status'
    # Security status
    if 'security status' in t or 'system status' in t or 'threat level' in t:
        return 'security_status'
    # System lockdown
    if 'system lockdown' in t or 'emergency mode' in t or 'lockdown mode' in t:
        return 'system_lockdown'
    
    return None  # Not a system command

# -------------------- AI Assistant (Groq) --------------------
def ask_groq(prompt):
    try:
        client = Groq(api_key=GROQ_API_KEY)
        completion = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[
                {
                    "role": "system",
                    "content": """You are an AI security assistant named 'Anonymous Security'.
Your job is to respond to voice commands with short, action-oriented confirmations.
Do NOT give long explanations. Just acknowledge the command and state what action is being taken.
Examples:
User: "Start system scan" → Assistant: "Scanning computer for malware…"
User: "Enable firewall" → Assistant: "Firewall activated"
User: "Scan USB devices" → Assistant: "Checking connected USB devices for threats"
User: "Block unknown USB" → Assistant: "Unknown USB devices blocked"
User: "Lock computer" → Assistant: "Computer locked"
User: "Shutdown system" → Assistant: "System shutdown initiated"
User: "Restart computer" → Assistant: "System restart initiated"
User: "Check security status" → Assistant: "All systems operational. Threat level: LOW"
"""
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            temperature=0.7,
            max_tokens=500
        )
        return completion.choices[0].message.content.strip()
    except Exception as e:
        print(f"❌ Groq error: {e}")
        return None

def mock_ai(prompt):
    p = prompt.lower()
    
    # System commands
    if any(x in p for x in ['lock computer', 'lock system', 'lock']):
        return "🔒 Computer locked (simulated)"
    if any(x in p for x in ['shutdown', 'shut down', 'turn off']):
        return "⚠️ System shutdown initiated (simulated)"
    if any(x in p for x in ['restart', 'reboot']):
        return "🔄 System restart initiated (simulated)"
    if 'firewall on' in p or 'enable firewall' in p:
        return "🔥 Firewall enabled"
    if 'firewall off' in p or 'disable firewall' in p:
        return "⚠️ Firewall disabled"
    if 'quick scan' in p or 'fast scan' in p:
        return "🛡️ Quick scan started... Scanning critical areas..."
    if 'deep scan' in p or 'full scan' in p:
        return "🔍 Deep scan started... Full system analysis in progress..."
    if 'malware scan' in p or 'virus scan' in p:
        return "🦠 Malware scan initiated... Checking for threats..."
    if 'check processes' in p or 'show processes' in p:
        return "✅ All processes running normally"
    if 'kill malware' in p or 'stop malware' in p:
        return "🔪 Suspicious processes terminated"
    if 'block usb' in p or 'disable usb' in p:
        return "🚫 Unknown USB devices blocked"
    if 'usb status' in p or 'check usb' in p:
        return "🔌 USB Status: 2 devices connected, 0 threats"
    if 'security status' in p or 'system status' in p:
        return "🛡️ Security Status: All systems operational. Threat level: LOW"
    if 'system lockdown' in p or 'emergency mode' in p:
        return "🔐 SYSTEM LOCKDOWN activated. All external access blocked."
    
    # Regular AI responses
    if 'start system scan' in p or 'run quick scan' in p:
        return "🛡️ Scanning computer for malware…"
    if 'full system scan' in p:
        return "🔍 Starting full system scan…"
    if 'stop scan' in p:
        return "⏹️ Scan stopped."
    if 'check firewall' in p:
        return "✅ Firewall is active."
    if 'block suspicious ip' in p:
        return "🚫 Suspicious IP blocked."
    if 'scan usb' in p:
        return "🔌 Scanning USB devices for threats…"
    if 'detect badusb' in p:
        return "👀 Monitoring for BadUSB attacks."
    if 'check network' in p:
        return "🌐 No suspicious network activity."
    if 'open dashboard' in p:
        return "📊 Opening security dashboard…"
    if 'real-time protection' in p:
        return "🛡️ Real-time protection enabled."
    if 'show connected devices' in p:
        return "📱 Showing connected devices…"
    if 'kill suspicious process' in p:
        return "🔪 Suspicious process terminated."
    
    return "💡 Command not recognized. Please try again."

# -------------------- API Endpoints --------------------
@app.route('/api/scan-file', methods=['POST'])
def api_scan_file():
    if 'file' not in request.files:
        return jsonify({'success': False, 'error': 'No file'}), 400
    file = request.files['file']
    result = scan_file_vt(file.read(), file.filename)
    if 'error' in result:
        return jsonify({'success': False, 'error': result['error']}), 500
    return jsonify({'success': True, 'result': result})

@app.route('/api/scan-url', methods=['POST'])
def api_scan_url():
    data = request.get_json()
    url = data.get('url')
    if not url:
        return jsonify({'success': False, 'error': 'No URL'}), 400
    result = scan_url_vt(url)
    if 'error' in result:
        return jsonify({'success': False, 'error': result['error']}), 500
    return jsonify({'success': True, 'result': result})

@app.route('/api/scan-ports', methods=['POST'])
def api_scan_ports():
    data = request.get_json()
    target = data.get('target')
    if not target:
        return jsonify({'success': False, 'error': 'No target'}), 400
    range_type = data.get('range', 'common')
    if range_type == 'common':
        ports = COMMON_PORTS
    elif range_type == 'all':
        ports = range(1, 1025)
    else:
        start = data.get('start', 1)
        end = data.get('end', 1024)
        ports = range(int(start), int(end)+1)
    try:
        open_ports = scan_ports(target, ports)
        add_log('INFO', f'Port scan {target}: {open_ports}')
        return jsonify({'success': True, 'open_ports': open_ports})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/web-scan', methods=['POST'])
def api_web_scan():
    data = request.get_json()
    url = data.get('url')
    if not url:
        return jsonify({'success': False, 'error': 'No URL'}), 400
    parsed = urlparse(url)
    hostname = parsed.hostname or parsed.path
    if not hostname:
        return jsonify({'success': False, 'error': 'Invalid URL'}), 400
    ssl = check_ssl(hostname) if parsed.scheme == 'https' else {'valid': False}
    dirs = [check_directory(url, d) for d in ['admin', 'backup', '.git', 'wp-admin']]
    xss = check_xss(url)
    sqli = check_sqli(url)
    score = 100
    findings = []
    if not ssl.get('valid'):
        score -= 20
        findings.append({'type': 'SSL/TLS', 'severity': 'high', 'description': 'SSL invalid'})
    for d in dirs:
        if d.get('accessible'):
            score -= 15
            findings.append({'type': 'Directory Exposure', 'severity': 'medium', 'description': f'{d["path"]} accessible'})
    if xss.get('vulnerable'):
        score -= 25
        findings.append({'type': 'XSS', 'severity': 'high', 'description': xss.get('message')})
    if sqli.get('vulnerable'):
        score -= 30
        findings.append({'type': 'SQL Injection', 'severity': 'critical', 'description': sqli.get('message')})
    score = max(0, score)
    return jsonify({'success': True, 'score': score, 'findings': findings})

@app.route('/api/hash', methods=['POST'])
def api_hash():
    data = request.get_json()
    text = data.get('text', '')
    if not text:
        return jsonify({'success': False, 'error': 'No text'}), 400
    return jsonify({
        'success': True,
        'md5': hashlib.md5(text.encode()).hexdigest(),
        'sha1': hashlib.sha1(text.encode()).hexdigest(),
        'sha256': hashlib.sha256(text.encode()).hexdigest()
    })

@app.route('/api/password-check', methods=['POST'])
def api_password():
    data = request.get_json()
    pwd = data.get('password', '')
    if not pwd:
        return jsonify({'success': False, 'error': 'No password'}), 400
    score = 0
    feedback = []
    if len(pwd) >= 8: score += 1
    else: feedback.append('At least 8 chars')
    if any(c.isupper() for c in pwd): score += 1
    else: feedback.append('Add uppercase')
    if any(c.islower() for c in pwd): score += 1
    else: feedback.append('Add lowercase')
    if any(c.isdigit() for c in pwd): score += 1
    else: feedback.append('Add numbers')
    if any(c in '!@#$%^&*' for c in pwd): score += 1
    else: feedback.append('Add special chars')
    common = ['password', '123456', 'qwerty', 'abc123']
    if pwd.lower() in common:
        score = 0
        feedback = ['Too common']
    labels = ['Very Weak', 'Weak', 'Fair', 'Good', 'Strong', 'Very Strong']
    return jsonify({'success': True, 'result': {'score': score, 'label': labels[score], 'feedback': feedback}})

@app.route('/api/encrypt', methods=['POST'])
def api_encrypt():
    data = request.get_json()
    text = data.get('text', '')
    if not text:
        return jsonify({'success': False, 'error': 'No text'}), 400
    encrypted = cipher.encrypt(text.encode())
    return jsonify({'success': True, 'ciphertext': base64.urlsafe_b64encode(encrypted).decode()})

@app.route('/api/decrypt', methods=['POST'])
def api_decrypt():
    data = request.get_json()
    ct = data.get('ciphertext', '')
    if not ct:
        return jsonify({'success': False, 'error': 'No ciphertext'}), 400
    try:
        decoded = base64.urlsafe_b64decode(ct.encode())
        plain = cipher.decrypt(decoded).decode()
        return jsonify({'success': True, 'plaintext': plain})
    except:
        return jsonify({'success': False, 'error': 'Decryption failed'}), 400

@app.route('/api/network-connections', methods=['GET'])
def api_connections():
    conns = []
    for conn in psutil.net_connections(kind='inet'):
        try:
            conns.append({
                'local_addr': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else '',
                'remote_addr': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else '',
                'status': conn.status,
                'pid': conn.pid
            })
        except:
            pass
    return jsonify({'success': True, 'connections': conns[:50]})

# -------------------- USB MOCK --------------------
MOCK_USB = [
    {'vendor': 'Kingston', 'product': 'DataTraveler', 'serial': 'ABC123', 'connected': True},
    {'vendor': 'SanDisk', 'product': 'Ultra Fit', 'serial': 'XYZ789', 'connected': False}
]

@app.route('/api/usb/devices', methods=['GET'])
def usb_devices():
    if random.random() > 0.7:
        MOCK_USB[0]['connected'] = not MOCK_USB[0]['connected']
    return jsonify({'success': True, 'devices': MOCK_USB})

@app.route('/api/usb/simulate-attack', methods=['POST'])
def usb_attack():
    attack = random.choice(['Keystroke injection', 'HID spoofing', 'Malicious firmware'])
    add_log('WARNING', f'Simulated attack: {attack}')
    return jsonify({'success': True, 'alert': f'⚠️ Simulated {attack} attack detected and blocked!', 'attack_type': attack})

@app.route('/api/usb/block', methods=['POST'])
def usb_block():
    add_log('INFO', 'USB blocking triggered (simulated)')
    return jsonify({'success': True, 'alert': '🚫 Unknown USB devices blocked (simulated).'})

# -------------------- AI Chat with Voice Command Support --------------------
@app.route('/api/ai-chat', methods=['POST'])
def ai_chat():
    data = request.get_json()
    msg = data.get('message', '')
    is_voice = data.get('is_voice', False)
    
    if not msg:
        return jsonify({'success': False, 'error': 'No message'}), 400
    
    # Check if it's a system command (voice or text)
    if is_voice or data.get('is_command', False):
        cmd = parse_voice_command(msg)
        if cmd:
            success, response = execute_system_command(cmd)
            add_log('INFO', f'Voice command: {msg} → {cmd}')
            return jsonify({'success': success, 'reply': response, 'command': cmd})
    
    # Regular AI chat
    reply = None
    if AI_PROVIDER == 'groq' and GROQ_API_KEY:
        reply = ask_groq(msg)
    
    if reply is None:
        reply = mock_ai(msg)
        
    return jsonify({'success': True, 'reply': reply})

# Direct system command endpoint
@app.route('/api/system/command', methods=['POST'])
def system_command():
    data = request.get_json()
    cmd = data.get('command', '')
    
    if not cmd:
        return jsonify({'success': False, 'error': 'No command'}), 400
    
    success, response = execute_system_command(cmd)
    add_log('INFO', f'Command executed: {cmd}')
    
    return jsonify({'success': success, 'reply': response, 'command': cmd})

# -------------------- System Logs & Stats --------------------
@app.route('/api/system/logs', methods=['GET'])
def get_logs():
    with log_lock:
        return jsonify({'success': True, 'logs': list(logs)})

@app.route('/api/system/clear-logs', methods=['POST'])
def clear_logs():
    with log_lock:
        logs.clear()
        return jsonify({'success': True})

@app.route('/api/system/stats', methods=['GET'])
def system_stats():
    return jsonify({'success': True, **get_system_stats()})

# -------------------- Frontend --------------------
@app.route('/')
def index():
    return render_template('index.html')

# -------------------- Error Handlers --------------------
@app.errorhandler(404)
def not_found(e):
    return jsonify({'success': False, 'error': 'Not found'}), 404

@app.errorhandler(500)
def internal_error(e):
    add_log('ERROR', f'500: {str(e)}')
    return jsonify({'success': False, 'error': 'Internal error'}), 500

# -------------------- Run --------------------
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)