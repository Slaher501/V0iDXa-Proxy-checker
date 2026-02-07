# 🌌 V0iDXa: High-Performance Proxy Intelligence Engine
### Advanced Reconnaissance & Multi-Protocol Validation Platform for Cybersecurity Professionals

> **"V0iDXa (Void‑X) is not just a checker. It is a Proxy Intelligence Engine."**

V0iDXa is a **professional-grade Proxy Intelligence Engine** designed for advanced cybersecurity operations.  
It goes far beyond basic proxy validation by **dissecting every IP into a full intelligence profile**, enabling informed, strategic decisions in hostile or restricted network environments.

This project is built for practitioners—not hobbyists.

---

## 🧠 Core Philosophy

> **"Every proxy is a network entity with behavior, risk, and operational value."**

V0iDXa treats proxies as **intelligence assets**, not disposable endpoints.  
Each IP is analyzed, scored, classified, and persisted to build long-term network awareness.

---

## 🛡️ Key Intelligence Modules

### 📡 1. Intelligent Data Ingestion

> **"Fresh intelligence starts with aggressive collection."**

- **Multi‑Source Scraping**  
  Aggregates proxies from **30+ curated public sources**.

- **Dynamic Discovery**  
  Integrated **GitHub API reconnaissance** to discover newly published and unindexed proxy lists.

- **Auto‑Sanitization**  
  - Deduplication  
  - Protocol normalization  
  - Full support for **HTTP, SOCKS4, SOCKS5**

---

### 🧠 2. OSINT & Geo‑Reconnaissance

> **"Context turns IPs into intelligence."**

- **ISP & ASN Mapping**  
  Identifies service providers (e.g., STC, Comcast, OVH) and Autonomous System Numbers.

- **Connection Classification**  
  - Residential (High Trust)  
  - Datacenter (Low Trust)

- **Precision Geolocation**  
  Country, city, and **real RTT‑based latency analysis**.

---

### 🕵️ 3. Anonymity & Stealth Profiling

> **"Anonymity is measurable."**

- **Anonymity Level Detection**  
  Advanced header analysis classifies proxies as:
  - ELITE  
  - ANONYMOUS  
  - TRANSPARENT  

- **Google Intelligence Test**  
  Detects:
  - `G:PASS`
  - CAPTCHA triggers
  - Hard IP blocks

- **SSL / TLS Validation**  
  - HTTPS capability verification  
  - TLS version detection (up to **TLS 1.3**)

---

### 🏎️ 4. Performance & Persistence

> **"Speed without reliability is noise."**

- **Throughput Benchmarking**  
  Real‑world **1MB download test** to calculate actual Mbps.

- **SQLite Persistence Layer**  
  Every validated proxy is stored for:
  - Historical tracking  
  - Burn detection  
  - Behavioral trend analysis  

- **Visual Intelligence Output**  
  GeoJSON generation to **visualize your proxy fleet globally**.

---

## 📊 Technical Output Format

> **"Structured output enables automation."**

Each proxy result is emitted in a **machine‑ and human‑readable format**:

socks5://1.2.3.4:1080 | US | Comcast | RES | 120ms | ELITE | G:PASS | 12.4 Mbps | ULTRA | SSL:TLS1.3


**Field Breakdown:**
- Protocol & Endpoint  
- Country  
- ISP  
- Connection Type  
- Latency  
- Anonymity Level  
- Google Status  
- Throughput  
- Quality Score  
- TLS Capability  

---

## ⚙️ Installation & Deployment

### Prerequisites
- Python **3.9+**
- `pip` package manager

---

### 1️⃣ Clone the Repository
```bash
git clone https://github.com/slaher501/V0iDXa.git
cd V0iDXa
2️⃣ Install Dependencies
pip install -r requirements.txt
3️⃣ Execute the Engine
python V0iDXa.py
Launches an interactive intelligence-driven menu.

📂 Project Structure
V0iDXa/
├── V0iDXa.py           # Core Intelligence Engine
├── requirements.txt    # Dependency Stack
├── proxies.db          # SQLite Intelligence Store (Auto-generated)
├── exports/            # JSON / CSV / TXT Output
└── README.md           # Documentation
🧩 Professional Use Cases
"Built for real operations."

Penetration Testing (Pivoting, Evasion, Prep)

OSINT under network restrictions

Large‑scale scraping with reduced ban rates

Proxy pool lifecycle management

Distributed automation pipelines

⚠️ Disclaimer
"Power requires responsibility."

This tool is intended only for educational purposes and authorized security research.
The developer (slaher501) assumes no liability for misuse or damages caused by this software.

Use responsibly. Stay legal.

💡 Closing Thought
"If you know, you win. If you don't, you learn the hard way."

