# 🛡️ CyberGuard Forensic API

**CyberGuard** is an enterprise-grade REST API designed for automated web forensics and phishing detection. It empowers security researchers and SOC analysts to perform deep audits on suspicious URLs, detect server-side evasion techniques, and analyze network infrastructure in real-time.

---

## ✨ Key Features

* **Network Reconnaissance:** Automatic IP resolution and scanning of critical infrastructure ports (21, 22, 80, 443, etc.).
* **Anti-Cloaking Detection:** Identifies if a server is serving different content to different User-Agents (e.g., hiding from Googlebots).
* **Signature Analysis:** Regex-based engine to detect malicious patterns like `credential`, `secure-login`, and `update-account`.
* **SSL Auditing:** Automated validation of SSL certificates and protocols.
* **Evidence Snapshots:** Integration with visual snapshot services to capture the state of the target site.
* **High Performance:** Built with **FastAPI** and `asyncio` for non-blocking forensic operations.

---

## 🚀 Quick Start

### 1. Prerequisites
Ensure you have **Python 3.8+** installed on your system.

### 2. Installation
```bash
# Clone the repository
git clone [https://github.com/khatar1/CyberGuard-API.git](https://github.com/khatar1/CyberGuard-API.git)
cd CyberGuard-API

# Install required dependencies
pip install fastapi uvicorn requests tldextract pydantic
- **SSL Metadata Extraction:** Deep analysis of SSL certificate validity and issuer authority.
- **Signature-Based Detection:** Regex-powered engine to scan for phishing patterns and credential-harvesting indicators.



## 🚀 Deployment & Installation

### Prerequisites
- Python 3.9+
- Pydroid 3 (for mobile) or Termux/PC Terminal

### Quick Start
1. **Clone the repository:**
   ```bash
   git clone [https://github.com/khatar1/CyberGuard-Forensics.git](https://github.com/khatar1/CyberGuard-Forensics.git)
   cd CyberGuard-Forensics

