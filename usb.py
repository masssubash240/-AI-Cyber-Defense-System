# usb_defense_fixed.py
import subprocess
import time
import sys
import os
import json
import ctypes
from datetime import datetime

# 🛡️ BadUSB IDs (உங்கள் Digispark ID சேர்க்கப்பட்டது)
BAD_USB_IDS = [
    "VID_16C0&PID_27DB",  # உங்கள் Digispark ID
    "VID_16D0&PID_0753",  # Digispark Default
    "VID_16D0&PID_075A",  # Digispark Pro
    "VID_1209&PID_2488",  # Common BadUSB
    "Digispark", "Rubber Ducky", "BadUSB"
]

LOG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "usb_defense_log.txt")

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def log_message(message):
    """UTF-8 Encoding-டன் Log எழுத"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    # Emoji-க்கு பதில் டெக்ஸ்ட் பயன்படுத்த
    message = message.replace("⚠️", "[WARNING]")
    message = message.replace("✅", "[OK]")
    message = message.replace("❌", "[ERROR]")
    message = message.replace("🛡️", "[DEFENSE]")
    message = message.replace("🚫", "[BLOCKED]")
    message = message.replace("🔍", "[SCAN]")
    
    full_msg = f"[{timestamp}] {message}"
    print(full_msg)
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(full_msg + "\n")
    except Exception as e:
        print(f"Log error: {e}")

def get_usb_devices():
    """USB டிவைஸ்களை பட்டியலிட"""
    try:
        cmd = [
            "powershell",
            "-ExecutionPolicy", "Bypass",
            "-Command",
            "Get-PnpDevice -PresentOnly | Where-Object { $_.Class -eq 'USB' -or $_.Class -eq 'HIDClass' } | Select-Object InstanceId, FriendlyName, Status | ConvertTo-Json"
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10, 
                               creationflags=subprocess.CREATE_NO_WINDOW, 
                               encoding="utf-8")
        if result.returncode == 0 and result.stdout.strip():
            data = json.loads(result.stdout)
            if isinstance(data, dict):
                return [data]
            return data if isinstance(data, list) else []
        return []
    except Exception as e:
        log_message(f"[ERROR] Scan error: {e}")
        return []

def block_device(instance_id):
    """டிவைஸை Disable செய்ய"""
    try:
        cmd = [
            "powershell",
            "-ExecutionPolicy", "Bypass",
            "-Command",
            f"Disable-PnpDevice -InstanceId '{instance_id}' -Confirm:$false"
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10,
                               creationflags=subprocess.CREATE_NO_WINDOW,
                               encoding="utf-8")
        if result.returncode == 0:
            return True
        else:
            log_message(f"[ERROR] Block failed: {result.stderr}")
            return False
    except Exception as e:
        log_message(f"[ERROR] Block error: {e}")
        return False

def monitor_usb():
    """தொடர்ந்து கண்காணிக்க"""
    log_message("[DEFENSE] USB Defense Started - Monitoring for BadUSB...")
    blocked_devices = set()
    
    while True:
        try:
            devices = get_usb_devices()
            for dev in devices:
                instance_id = dev.get('InstanceId', '')
                friendly_name = dev.get('FriendlyName', '')
                status = dev.get('Status', '')
                
                if not instance_id:
                    continue
                
                # BadUSB இருக்கிறதா என சோதிக்க
                is_bad = False
                for bad_id in BAD_USB_IDS:
                    if bad_id.lower() in instance_id.lower() or bad_id.lower() in friendly_name.lower():
                        is_bad = True
                        break
                
                # தடுக்கப்பட்ட டிவைஸ் மீண்டும் இணைக்கப்பட்டதா என பார்க்க
                if is_bad and status == 'OK' and instance_id not in blocked_devices:
                    log_message(f"[WARNING] THREAT DETECTED: {friendly_name} ({instance_id})")
                    if block_device(instance_id):
                        blocked_devices.add(instance_id)
                        log_message(f"[BLOCKED] Device blocked: {instance_id}")
                    else:
                        log_message(f"[ERROR] Block failed: {instance_id}")
            
            time.sleep(1)  # ஒவ்வொரு 1 வினாடியும் ஸ்கேன்
        except KeyboardInterrupt:
            log_message("[DEFENSE] Stopped by user")
            break
        except Exception as e:
            log_message(f"[ERROR] Loop error: {e}")
            time.sleep(3)

if __name__ == "__main__":
    print("=" * 60)
    print("[DEFENSE] Anonymous Security - USB Defense v3 (Fixed)")
    print("=" * 60)
    
    # Admin உரிமை இல்லையெனில் மீண்டும் Admin-ல் ஓட்ட முயற்சி
    if not is_admin():
        print("[ERROR] Administrator Rights Required!")
        print("[DEFENSE] Restarting with Admin privileges...")
        try:
            ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
        except Exception as e:
            print(f"[ERROR] Auto-elevation failed: {e}")
            print("[WARNING] Please run manually as Administrator!")
        sys.exit(0)
    
    print("[OK] Admin Rights Confirmed")
    print(f"[SCAN] Monitoring USB devices...")
    print(f"[SCAN] BadUSB IDs: {', '.join(BAD_USB_IDS[:3])}")
    print("=" * 60)
    monitor_usb()