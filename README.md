# Scrappy-python-crawler
🕵️‍♂️ Advanced Threat Intelligence & Typosquat Scanner

A next-generation threat detection tool designed for security researchers, penetration testers, and organizations to identify typosquatting domains, phishing threats, and suspicious web activities. It combines asynchronous crawling, headless browser rendering, DNS & WHOIS intelligence, and risk scoring to provide a complete picture of potential threats.

Features

Comprehensive typosquat generation

Homoglyph substitution, character omission/duplication, swaps, TLD tricks, subdomains, compound domains, bitsquatting.

Advanced domain scanning

DNS resolution (A, MX, NS)

WHOIS information retrieval

HTTP(S) fetch with fallback (Playwright headless browser → aiohttp)

Phishing & malicious indicators detection

Hidden forms, password fields, iframes

Suspicious keywords and obfuscated JavaScript

External links and JS file analysis

Similarity scoring against legitimate site

Detect potential typosquatting/phishing clones using HTML similarity metrics

Automated risk scoring

Weighted scoring based on similarity, phishing indicators, forms, redirects, and keywords

Screenshot & HTML hash

Capture visual proof and unique HTML fingerprints

Database persistence

SQLite for scans and threats

Indexed for fast queries and reporting

Asynchronous & concurrent scanning

Efficient scanning of hundreds of typosquats or subdomains

Comprehensive JSON reports

Categorized threats (Critical, Medium, Low)

Full metadata for further analysis

Advantages

Proactive threat detection – Identify phishing and typo domains before they impact users.

Full-stack automation – Crawls, renders, and analyzes web pages without manual intervention.

Cross-domain intelligence – Combines DNS, WHOIS, HTML analysis, and JS execution.

Educational & research-ready – Ideal for security analysts and cybersecurity training.

Highly configurable & extensible – Easy to expand with new indicators or scoring rules.

Installation
# Clone repo
git clone https://github.com/yourusername/typosquat-threat-scanner.git
cd typosquat-threat-scanner

# Install dependencies
pip install aiohttp dnspython certifi beautifulsoup4 playwright python-whois

# Install Playwright browser
playwright install chromium

Usage
# Run scanner on a target domain
python scanner.py

# Example: scan paypal.com
# Will generate typosquat domains, fetch pages, analyze for phishing, and generate JSON report

Example Output
======================================================================
THREAT INTELLIGENCE REPORT
======================================================================
Target: paypal.com
Scan ID: 12

Summary:
  Total checked: 100
  Active domains: 87
  🔴 High risk: 5
  🟡 Medium risk: 10
  🟢 Low risk: 72

======================================================================
🚨 CRITICAL THREATS:
======================================================================

  Domain: paypa1.com
  Risk Score: 85/100
  Similarity: 92.34%
  IPs: 192.168.1.12
  Indicators: Hidden forms detected, Phishing keyword: verify your account

Key Commands & Techniques

Asynchronous scanning with asyncio for high concurrency

Playwright headless browser for JS-heavy page rendering

DNS & WHOIS checks to validate domain existence

HTML similarity scoring via difflib.SequenceMatcher

SQLite persistence for long-term analysis

Advanced typosquat generation covering all common attack vectors

Romanian Version 🇷🇴
🕵️‍♂️ Scanner Avansat de Amenințări & Typosquatting

Un instrument de ultimă generație pentru securitate, destinat cercetătorilor, testerilor de penetrare și organizațiilor pentru a identifica domenii typosquat, phishing și activități web suspecte. Combină crawling asincron, browser headless, DNS & WHOIS intelligence și scoring de risc pentru analiza completă a amenințărilor.

Funcționalități

Generare typosquat avansată

Homoglyph, omiterea/duplicarea caracterelor, swap-uri, TLD greșite, subdomenii, domenii compuse, bitsquatting

Scanare domenii avansată

Rezoluție DNS (A, MX, NS)

Informații WHOIS

Fetch HTTP(S) cu fallback (Playwright → aiohttp)

Detectare phishing & indicatori rău intenționați

Formulare ascunse, câmpuri password, iframe-uri

Cuvinte cheie suspecte și JS obfuscat

Analiza linkurilor externe și fișierelor JS

Scoring similaritate site legitim

Detectare cloni typosquat/phishing cu metrici HTML

Scoring automat de risc

Ponderare după similaritate, indicatori phishing, formulare, redirects, keywords

Captură screenshot & hash HTML

Dovezi vizuale și fingerprint unic

Persistență în bază de date

SQLite pentru scanări și amenințări

Indexare pentru interogări rapide

Scanare asincronă & concurentă

Scanare eficientă a sute de domenii

Rapoarte JSON complete

Amenințări categorizate (Critic, Mediu, Scăzut)

Metadata completă pentru analiză suplimentară

Avantaje

Detectare proactivă a amenințărilor – Identifică phishing și typosquat înainte de impact.

Automatizare completă – Crawlează, renderizează și analizează paginile fără intervenție manuală.

Inteligență multi-domeniu – Combină DNS, WHOIS, analiza HTML și execuția JS.

Instrument educațional & de cercetare – Ideal pentru analiști de securitate și training cybersecurity.

Configurabil & extensibil – Se pot adăuga ușor noi indicatori sau reguli de scoring.

Instalare
# Clone repo
git clone https://github.com/username/typosquat-threat-scanner.git
cd typosquat-threat-scanner

# Instalează dependințele
pip install aiohttp dnspython certifi beautifulsoup4 playwright python-whois

# Instalează browser Playwright
playwright install chromium

Utilizare
# Rulează scanner pe un domeniu țintă
python scanner.py

# Exemplu: scan paypal.com
# Va genera domenii typosquat, va analiza paginile pentru phishing și va crea raport JSON

Rezumat Output
======================================================================
RAPORT AMENINȚĂRI
======================================================================
Target: paypal.com
Scan ID: 12

Summary:
  Total verificat: 100
  Domenii active: 87
  🔴 Risc ridicat: 5
  🟡 Risc mediu: 10
  🟢 Risc scăzut: 72

======================================================================
🚨 AMENINȚĂRI CRITICE:
======================================================================

  Domeniu: paypa1.com
  Scor Risc: 85/100
  Similaritate: 92.34%
  IPs: 192.168.1.12
  Indicatori: Formulare ascunse detectate, Cuvânt phishing: verify your account
