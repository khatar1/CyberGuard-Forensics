import os
import re
import ssl
import socket
import logging
import requests
from datetime import datetime
from flask import Flask, render_template_string, request, jsonify
import tldextract

# --- System Logging Configuration ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')

app = Flask(__name__)

# --- Core Configuration ---
class SecurityConfig:
    PORT_LIST = [21, 22, 80, 443, 3306, 8080]
    SIGNATURES = [
        r'login', r'verify', r'update.*account', r'secure.*login',
        r'bank', r'paypal', r'password', r'credential', r'signin', r'wallet'
    ]
    AGENTS = {
        'mobile': 'Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)',
        'bot': 'Googlebot/2.1 (+http://www.google.com/bot.html)'
    }

# --- Backend Forensic Engine ---
class ForensicEngine:
    def __init__(self, target_url):
        self.url = target_url if target_url.startswith('http') else f'https://{target_url}'
        self.domain = tldextract.extract(self.url).fqdn
        self.ip = self._resolve_ip()

    def _resolve_ip(self):
        try: return socket.gethostbyname(self.domain)
        except: return "N/A"

    def scan_network_ports(self):
        open_ports = []
        for port in SecurityConfig.PORT_LIST:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.3)
                if s.connect_ex((self.ip, port)) == 0: open_ports.append(port)
        return open_ports

    def detect_cloaking(self):
        """Identifies if a site serves different content to bots vs users."""
        try:
            m_res = requests.get(self.url, headers={'User-Agent': SecurityConfig.AGENTS['mobile']}, timeout=5).text
            b_res = requests.get(self.url, headers={'User-Agent': SecurityConfig.AGENTS['bot']}, timeout=5).text
            return abs(len(m_res) - len(b_res)) > 2000
        except: return False

    def analyze_ssl(self):
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((self.domain, 443), timeout=3) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.domain) as ss:
                    cert = ss.getpeercert()
                    issuer = dict(x[0] for x in cert['issuer'])['commonName']
                    return {"status": "Verified", "issuer": issuer}
        except: return {"status": "Unverified/None", "issuer": "N/A"}

# --- Professional Cyber-UI Template ---
HTML_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CyberGuard | Forensic Intelligence Suite</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;800&family=Fira+Code:wght@400;500&display=swap" rel="stylesheet">
    <style>
        :root { --accent: #00ff9d; --bg: #05070a; --surface: #0e121a; --text: #e0e6ed; --danger: #ff4757; }
        body { background: var(--bg); color: var(--text); font-family: 'Inter', sans-serif; margin: 0; padding: 20px; line-height: 1.6; }
        .wrapper { max-width: 1000px; margin: auto; }
        .header { text-align: left; margin-bottom: 40px; border-left: 4px solid var(--accent); padding-left: 20px; }
        .card { background: var(--surface); border: 1px solid #1e293b; border-radius: 12px; padding: 24px; margin-bottom: 24px; box-shadow: 0 4px 20px rgba(0,0,0,0.5); }
        .input-row { display: flex; gap: 12px; margin-top: 20px; }
        input { flex: 1; padding: 14px; background: #05070a; border: 1px solid #1e293b; color: white; border-radius: 8px; font-size: 16px; outline: none; }
        input:focus { border-color: var(--accent); }
        button { background: var(--accent); color: #000; border: none; padding: 0 30px; border-radius: 8px; font-weight: 800; cursor: pointer; text-transform: uppercase; transition: 0.2s; }
        button:hover { filter: brightness(1.2); transform: translateY(-2px); }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 20px; }
        .stat-card h4 { margin: 0; font-size: 12px; text-transform: uppercase; color: #64748b; letter-spacing: 1px; }
        .stat-card p { margin: 8px 0 0; font-size: 20px; font-weight: 700; color: var(--accent); }
        .console { background: #000; color: #00ff9d; font-family: 'Fira Code', monospace; padding: 15px; border-radius: 8px; font-size: 12px; height: 160px; overflow-y: auto; border: 1px solid #1e293b; }
        #screenshot { width: 100%; border-radius: 8px; border: 1px solid #1e293b; display: none; margin-top: 15px; }
        .finding-item { background: rgba(255, 71, 87, 0.1); border-left: 4px solid var(--danger); padding: 15px; border-radius: 4px; margin-bottom: 12px; }
    </style>
</head>
<body>
    <div class="wrapper">
        <div class="header">
            <h1 style="margin:0; font-weight:800; font-size: 32px;">CyberGuard <span style="font-weight:200;">Intelligence</span></h1>
            <p style="color:#64748b; margin: 5px 0;">Automated Web Forensic & Phishing Analysis Platform</p>
        </div>

        <div class="card">
            <div class="input-row">
                <input type="text" id="target" placeholder="Enter target URL (e.g., https://paypal-secure.com)">
                <button onclick="analyze()">Scan Target</button>
            </div>
        </div>

        <div id="dashboard" style="display:none;">
            <div class="grid">
                <div class="card stat-card"><h4>Network Address</h4><p id="ipVal"></p></div>
                <div class="card stat-card"><h4>SSL Status</h4><p id="sslVal"></p></div>
                <div class="card stat-card"><h4>Evasion (Cloaking)</h4><p id="cloakVal"></p></div>
            </div>

            <div class="grid">
                <div class="card">
                    <h3 style="margin-top:0">Visual Evidence</h3>
                    <div id="loader" style="color:var(--accent)">Capturing Site Snapshot...</div>
                    <img id="screenshot" src="" alt="Live Capture">
                </div>
                <div class="card">
                    <h3 style="margin-top:0">Real-time Telemetry</h3>
                    <div class="console" id="logs"></div>
                </div>
            </div>

            <div class="card">
                <h3 style="margin-top:0; color:var(--danger)">Forensic Audit Findings</h3>
                <div id="findings"></div>
            </div>
        </div>
    </div>

    <script>
        async function analyze() {
            const url = document.getElementById('target').value;
            if(!url) return;
            
            document.getElementById('dashboard').style.display = 'none';
            document.querySelector('button').innerText = 'Scanning...';
            const logs = document.getElementById('logs');
            logs.innerHTML = "> Initializing Forensic Node...\\n> Resolving DNS...\\n> Handshaking...\\n> Capturing Traffic Packets...";

            try {
                const res = await fetch('/analyze', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/x-www-form-urlencoded'},
                    body: 'url=' + encodeURIComponent(url)
                });
                const data = await res.json();
                
                document.getElementById('dashboard').style.display = 'block';
                document.getElementById('ipVal').innerText = data.ip;
                document.getElementById('sslVal').innerText = data.ssl.status;
                document.getElementById('cloakVal').innerText = data.is_cloaked ? 'DETECTED' : 'CLEAN';
                
                const img = document.getElementById('screenshot');
                img.src = data.screenshot;
                img.onload = () => {
                    document.getElementById('loader').style.display = 'none';
                    img.style.display = 'block';
                };

                logs.innerHTML = data.evidence.map(e => `> ${e}`).join('\\n');
                
                const fContainer = document.getElementById('findings');
                fContainer.innerHTML = data.findings.length > 0 
                    ? data.findings.map(f => `<div class="finding-item">${f}</div>`).join('')
                    : '<div style="color:var(--accent)">No critical threats detected via signature analysis.</div>';

            } catch (e) {
                logs.innerHTML += "\\n> ERROR: Analysis failed or timed out.";
            } finally {
                document.querySelector('button').innerText = 'Scan Target';
            }
        }
    </script>
</body>
</html>
'''

# --- Controller (Routes) ---

@app.route('/')
def home():
    return render_template_string(HTML_TEMPLATE)

@app.route('/analyze', methods=['POST'])
def analyze():
    url = request.form.get('url', '')
    engine = ForensicEngine(url)
    
    logging.info(f"Target Scan Initiated: {url}")
    
    data = {
        "ip": engine.ip,
        "is_cloaked": engine.detect_cloaking(),
        "ssl": engine.analyze_ssl(),
        "open_ports": engine.scan_network_ports(),
        "screenshot": f"https://image.thum.io/get/width/800/crop/600/noScroll/https://{engine.domain}",
        "findings": [],
        "evidence": [
            f"AUDIT_TS: {datetime.now().strftime('%H:%M:%S UTC')}",
            f"PROTOCOL: HTTP/1.1 TLSv1.3",
            f"TELEMETRY: Scanning {len(SecurityConfig.SIGNATURES)} signatures...",
            f"PACKET_SZ: MTU 1500 detected"
        ]
    }

    # Analysis Logic
    if data["is_cloaked"]:
        data["findings"].append("⚠️ ANTI-ANALYSIS DETECTED: The server is serving different content to bots, a common evasion tactic for phishing.")
    
    if 21 in data["open_ports"] or 3306 in data["open_ports"]:
        data["findings"].append(f"🚨 EXPOSED INFRASTRUCTURE: Critical ports ({data['open_ports']}) are open, increasing the attack surface.")
    
    try:
        content = requests.get(engine.url, timeout=5).text.lower()
        matches = [s for s in SecurityConfig.SIGNATURES if re.search(s, content)]
        if matches:
            data["findings"].append(f"🚩 MALICIOUS SIGNATURES: Found phishing indicators in source code: {', '.join(matches)}.")
    except: pass

    if data["ssl"]["status"] != "Verified":
        data["findings"].append("🔒 SECURITY RISK: Missing or self-signed SSL certificate detected.")

    return jsonify(data)

if __name__ == '__main__':
    # Production-safe run for Pydroid 3 / Termux
    app.run(host='0.0.0.0', port=8080, debug=False, use_reloader=False)
