
# 🛡️ AI Cyber Defense System

### AI-Powered Cybersecurity Dashboard & Threat Detection Platform

![Image](https://cdn.dribbble.com/userupload/43439112/file/original-9b2d76da668971a2fa5a1914729b4671.png?resize=400x0)

![Image](https://images.openai.com/static-rsc-3/zMmuuv7slYneuBg-FxCvQ8CwXAd5B-QjEnhIEPtPgTaAXEJmw8L77CKDNG-KzG83s4NcScrGcpu0i-NiA6eIWQybyha9K-PnN2dYsJrcQTQ?purpose=fullsize\&v=1)

![Image](https://elements-resized.envatousercontent.com/elements-video-cover-images/df10bc55-3150-43bf-add1-9daa707f10cd/video_preview/video_preview_0002.jpg?cf_fit=cover\&format=auto\&q=85\&s=865924521a116e4a3bf8ed456930686d8ef2393e3823cb9a739274142cd9d958\&w=500)

![Image](https://elements-resized.envatousercontent.com/elements-video-cover-images/files/3e65d860-219e-4c4c-ac22-870d9559185b/inline_image_preview.jpg?cf_fit=crop\&format=jpeg\&h=630\&q=85\&s=d803d87b8c28653bb016ba5a11c68ccb06729ab2b63a036263c76835b3311e99\&w=1200)

An **AI-powered cybersecurity defense system** designed to detect malware, analyze threats, scan networks, and protect systems in real time.

This project combines:

* 🧠 AI Security Assistant
* 🛡️ Malware & URL Scanner
* 🌐 Network Port Scanner
* 🔌 USB Attack Detection (BadUSB / Rubber Ducky)
* 🔐 Encryption Tools
* 📊 Security Dashboard

Built using **Python, Flask, HTML, CSS, JavaScript**.

---

# 🚀 Features

## 🛡️ Security Dashboard

![Image](https://cdn.dribbble.com/userupload/45885505/file/c5a56fe0fa08264d815eeee91bb56aec.png?resize=2048x1536\&vertical=center)

![Image](https://www.progressive.in/assets/img/photos/SOC-Dashboard.webp?format=webp)

![Image](https://cdn.dribbble.com/userupload/16036468/file/original-7c4c61430b46c75d5fe60c8d7cd8fe65.png?format=webp\&resize=400x300\&vertical=center)

![Image](https://cdn.dribbble.com/userupload/46872347/file/be9f45049c1dbc51740b5c05927a9fbb.png?format=webp\&resize=400x300\&vertical=center)

Real-time monitoring of system security.

**Functions**

✔ Threat monitoring
✔ Scan statistics
✔ USB protection status
✔ Network security status
✔ Real-time logs

---

# 🦠 Malware & File Scanner

![Image](https://www.f-secure.com/i/1207x787/63c0da4872/online-scanner-image.png/m/fit-in/1920x0/filters%3Aquality%2890%29)

![Image](https://www.tenable.com/sites/default/files/images/sc-dashboards/EbM_Dashboard.png)

![Image](https://cdn.dribbble.com/userupload/8724095/file/original-406535addbc6f6f607062083c1057344.png?format=webp\&resize=400x300\&vertical=center)

![Image](https://cdn.dribbble.com/userupload/35903874/file/still-5b84c8a2f9af2c68e3b1d47799184b7d.png)

The system scans files and URLs using **VirusTotal API**.

**Capabilities**

* File malware scanning
* URL threat detection
* Quick system scan
* Deep system scan

API Endpoint used in backend:

```
/api/scan-file
/api/scan-url
```

---

# 🔌 USB Attack Protection (BadUSB Detection)

![Image](https://m.media-amazon.com/images/I/71-KfJZScdL._AC_UF1000%2C1000_QL80_.jpg)

![Image](https://media.springernature.com/lw685/springer-static/image/art%3A10.1007%2Fs44443-025-00067-6/MediaObjects/44443_2025_67_Fig33_HTML.png)

![Image](https://www.manageengine.com/device-control/images/port-security.png)

![Image](https://www.usb-lock-rp.com/usb_control_software.png)

Protects the system from malicious USB devices.

Detects:

* Rubber Ducky attacks
* HID spoofing
* Keystroke injection
* Malicious firmware

API example:

```
/api/usb/devices
/api/usb/simulate-attack
/api/usb/block
```

---

# 🌐 Network Scanner

![Image](https://www.w3schools.com/cybersecurity/img_pingsweep.svg)

![Image](https://www.mdpi.com/jcp/jcp-04-00012/article_deploy/html/images/jcp-04-00012-g006-550.jpg)

![Image](https://www.tenable.com/sites/default/files/images/sc-dashboards/VulnerabilitiesByCommonPortsrev2.png)

![Image](https://www.roboshadow.com/hs-fs/hubfs/Openports2.5.png?height=216\&name=Openports2.5.png\&width=586)

The system scans networks to detect open ports and vulnerabilities.

Functions:

✔ Port scanning
✔ Active connection monitoring
✔ Ping & DNS tools
✔ Network analysis

Example backend function:

```
scan_ports()
```

---

# 🌍 Web Vulnerability Scanner

Checks websites for security vulnerabilities.

Detects:

* XSS attacks
* SQL Injection
* Directory exposure
* SSL security issues

Example endpoint

```
/api/web-scan
```

---

# 🔐 Security Tools

Includes built-in cybersecurity tools.

Tools available:

* Password strength checker
* Hash generator
* Encryption / Decryption
* Port scanner

Example hash generation:

```
MD5
SHA1
SHA256
```

---

# 🤖 AI Security Assistant

The AI assistant helps users with cybersecurity commands.

Example commands:

```
Start malware scan
Enable firewall
Check security status
Block USB devices
Shutdown system
Lock computer
```

Backend AI handler:

```
/api/ai-chat
```

AI provider:

* Groq LLM
* Mock AI fallback

---

# 🏗️ Project Architecture

```
AI Cyber Defense System
│
├── frontend
│   ├── index.html
│   ├── CSS (cyber dashboard UI)
│   └── JavaScript logic
│
├── backend
│   ├── Flask server
│   ├── VirusTotal API integration
│   ├── Network scanner
│   ├── AI assistant
│   └── Encryption module
│
└── Security Modules
    ├── Malware scanner
    ├── USB guard
    ├── Web vulnerability scanner
    ├── Port scanner
```

Frontend dashboard code → 
Backend Flask server → 

---

# ⚙️ Installation

### 1️⃣ Clone Repository

```bash
git clone https://github.com/yourusername/AI-Cyber-Defense-System.git
cd AI-Cyber-Defense-System
```

---

### 2️⃣ Install Dependencies

```bash
pip install flask
pip install psutil
pip install requests
pip install cryptography
pip install python-dotenv
pip install groq
```

---

### 3️⃣ Run Server

```bash
python app.py
```

Server runs on:

```
http://localhost:5000
```

---

# 📊 Tech Stack

| Technology     | Usage             |
| -------------- | ----------------- |
| Python         | Backend           |
| Flask          | API Server        |
| HTML/CSS       | UI                |
| JavaScript     | Dashboard Logic   |
| VirusTotal API | Malware Detection |
| Groq AI        | AI Assistant      |
| psutil         | System Monitoring |

---

# 🎥 Demo Animation (README GIF)

You can add a GIF like this in GitHub:

```
![Demo](images/dashboard-demo.gif)
```

Recommended GIF ideas:

* malware scan animation
* dashboard animation
* network scan animation

---

# 👨‍💻 Author

**Subash Kumar**
Cybersecurity Student
SSREC College

Team Name:

```
Team Anonymous
```

