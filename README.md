# 🕵️‍♂️ Advanced Threat Intelligence & Typosquat Scanner

A **next-generation threat detection tool** designed for security researchers, penetration testers, and organizations to identify **typosquatting domains**, **phishing threats**, and **suspicious web activities**.

The scanner combines **asynchronous crawling**, **headless browser rendering**, **DNS & WHOIS intelligence**, and **automated risk scoring** to provide a complete, actionable picture of potential threats.

---

## 🚀 Features

### 🔤 Comprehensive Typosquat Generation
- Homoglyph substitution  
- Character omission & duplication  
- Character swaps  
- TLD manipulation  
- Subdomains & compound domains  
- Bitsquatting  

---

### 🌐 Advanced Domain Scanning
- DNS resolution (**A, MX, NS**)  
- WHOIS information retrieval  
- HTTP(S) fetching with smart fallback  
  - **Playwright (headless browser)**  
  - **aiohttp (async HTTP client)**  

---

### 🎯 Phishing & Malicious Indicators Detection
- Hidden forms & password fields  
- Iframes and embedded content  
- Suspicious phishing keywords  
- Obfuscated JavaScript  
- External link & JS file analysis  

---

### 🧬 Similarity Scoring
- HTML similarity comparison with legitimate website  
- Detection of cloned phishing or typosquat pages  

---

### ⚠️ Automated Risk Scoring
- Weighted scoring based on:
  - Page similarity
  - Phishing indicators
  - Forms & redirects
  - Keywords & scripts  

---

### 📸 Evidence Collection
- Full-page screenshots  
- Unique HTML hash fingerprints  

---

### 🗄️ Database Persistence
- SQLite storage for scans & threats  
- Indexed tables for fast querying  

---

### ⚡ Asynchronous & Concurrent Scanning
- Efficiently scan **hundreds of domains** in parallel  

---

### 📄 Comprehensive JSON Reports
- Threat classification:
  - 🔴 Critical  
  - 🟡 Medium  
  - 🟢 Low  
- Full metadata for further investigation  

---

## ✅ Advantages

- **Proactive threat detection** – Identify phishing and typo domains early  
- **Full automation** – Crawl, render, analyze, and score automatically  
- **Cross-domain intelligence** – DNS, WHOIS, HTML & JavaScript analysis  
- **Educational & research-ready** – Ideal for SOC teams and security training  
- **Highly extensible** – Easily add new indicators or scoring rules  

---

## 🛠️ Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/typosquat-threat-scanner.git
cd typosquat-threat-scanner

# Install dependencies
pip install aiohttp dnspython certifi beautifulsoup4 playwright python-whois

# Install Playwright browser
playwright install chromium
