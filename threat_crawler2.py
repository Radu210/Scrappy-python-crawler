import asyncio
import aiohttp
import dns.resolver
from urllib.parse import urlparse, urljoin
from datetime import datetime
import json
import hashlib
import re
from typing import List, Dict, Set, Optional
import ssl
import certifi
from bs4 import BeautifulSoup
from playwright.async_api import async_playwright, Browser, Page
import whois
from difflib import SequenceMatcher
import sqlite3
from dataclasses import dataclass, asdict
import logging
from pathlib import Path
import base64

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


@dataclass
class ThreatResult:
    """Structură pentru rezultate threat"""
    domain: str
    exists: bool
    ips: List[str]
    whois_data: Optional[Dict]
    status_code: Optional[int]
    title: str
    screenshot_path: Optional[str]
    html_hash: str
    similarity_score: float
    risk_score: int
    suspicious_keywords: List[str]
    phishing_indicators: List[str]
    ssl_info: Optional[Dict]
    redirects: List[str]
    forms_found: List[Dict]
    external_links: List[str]
    js_files: List[str]
    timestamp: str


class DatabaseManager:
    """Manager pentru persistență SQLite"""
    
    def __init__(self, db_path: str = "threat_intel.db"):
        self.db_path = db_path
        self.init_db()
    
    def init_db(self):
        """Inițializează schema DB"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_domain TEXT,
                scan_time TEXT,
                total_checked INTEGER,
                threats_found INTEGER
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS threats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER,
                domain TEXT,
                risk_score INTEGER,
                similarity_score REAL,
                ips TEXT,
                whois_data TEXT,
                html_hash TEXT,
                screenshot_path TEXT,
                indicators TEXT,
                timestamp TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans(id)
            )
        """)
        
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_domain ON threats(domain)
        """)
        
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_risk ON threats(risk_score)
        """)
        
        conn.commit()
        conn.close()
    
    def save_scan(self, target: str, results: List[ThreatResult]) -> int:
        """Salvează rezultatele unui scan"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        threats = [r for r in results if r.exists and r.risk_score > 30]
        
        cursor.execute("""
            INSERT INTO scans (target_domain, scan_time, total_checked, threats_found)
            VALUES (?, ?, ?, ?)
        """, (target, datetime.now().isoformat(), len(results), len(threats)))
        
        scan_id = cursor.lastrowid
        
        for threat in threats:
            cursor.execute("""
                INSERT INTO threats (
                    scan_id, domain, risk_score, similarity_score, ips,
                    whois_data, html_hash, screenshot_path, indicators, timestamp
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                scan_id, threat.domain, threat.risk_score, threat.similarity_score,
                json.dumps(threat.ips), json.dumps(threat.whois_data),
                threat.html_hash, threat.screenshot_path,
                json.dumps(threat.phishing_indicators), threat.timestamp
            ))
        
        conn.commit()
        conn.close()
        return scan_id


class AdvancedTypoGenerator:
    """Generator avansat de typosquats"""
    
    @staticmethod
    def generate_all(domain: str) -> Set[str]:
        """Generează toate tipurile de typosquats"""
        base = domain.split('.')[0]
        tld = domain.split('.')[-1] if '.' in domain else 'com'
        
        variants = set()
        
        homoglyphs = {
            'a': ['@', 'á', 'à', 'â'], 'e': ['3', 'é', 'è'],
            'i': ['1', 'l', '!', 'í'], 'o': ['0', 'ó', 'ò'],
            's': ['5', '$'], 'l': ['1', 'i'], 't': ['7'],
            'g': ['9', 'q'], 'b': ['8'], 'z': ['2']
        }
        
        for i, char in enumerate(base):
            if char.lower() in homoglyphs:
                for replacement in homoglyphs[char.lower()]:
                    variants.add(f"{base[:i]}{replacement}{base[i+1:]}.{tld}")
        
        for i in range(len(base)):
            variants.add(f"{base[:i]}{base[i+1:]}.{tld}")
        
        for i in range(len(base)):
            variants.add(f"{base[:i]}{base[i]}{base[i:]}.{tld}")
        
        for i in range(len(base) - 1):
            variants.add(f"{base[:i]}{base[i+1]}{base[i]}{base[i+2:]}.{tld}")
        
        common_tlds = ['com', 'net', 'org', 'co', 'io', 'ai', 'app', 'dev', 'info']
        for new_tld in common_tlds:
            if new_tld != tld:
                variants.add(f"{base}.{new_tld}")
        
        variants.add(f"www-{base}.{tld}")
        variants.add(f"m-{base}.{tld}")
        variants.add(f"{base}-login.{tld}")
        variants.add(f"{base}-secure.{tld}")
        variants.add(f"{base}-verify.{tld}")
        variants.add(f"{base}-account.{tld}")
        variants.add(f"secure-{base}.{tld}")
        variants.add(f"login-{base}.{tld}")
        variants.add(f"{base}online.{tld}")
        variants.add(f"{base}security.{tld}")
        
        variants.add(f"{base}{tld}.com")
        variants.add(f"{base}-{tld}.com")
        
        for i, char in enumerate(base):
            for bit in range(8):
                flipped = chr(ord(char) ^ (1 << bit))
                if flipped.isalnum():
                    variants.add(f"{base[:i]}{flipped}{base[i+1:]}.{tld}")
        
        return variants


class ThreatCrawler:
    """Crawler avansat pentru detectare phishing și typosquats"""
    
    def __init__(self, output_dir: str = "threat_data"):
        self.timeout = aiohttp.ClientTimeout(total=15)
        self.ssl_context = ssl.create_default_context(cafile=certifi.where())
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.screenshots_dir = self.output_dir / "screenshots"
        self.screenshots_dir.mkdir(exist_ok=True)
        self.db = DatabaseManager()
        self.browser: Optional[Browser] = None
        self.legitimate_html: Optional[str] = None
        self.legitimate_hash: Optional[str] = None
        
    async def init_browser(self):
        """Inițializează browser headless pentru rendering JS"""
        playwright = await async_playwright().start()
        self.browser = await playwright.chromium.launch(
            headless=True,
            args=['--no-sandbox', '--disable-setuid-sandbox']
        )
        logger.info("✓ Browser headless inițializat")
    
    async def close_browser(self):
        """Închide browser"""
        if self.browser:
            await self.browser.close()
    
    async def check_dns(self, domain: str) -> Dict:
        """Verificare DNS avansată (A, MX, NS)"""
        result = {'exists': False, 'ips': [], 'mx': [], 'ns': []}
        
        try:
            answers = dns.resolver.resolve(domain, 'A')
            result['ips'] = [str(rdata) for rdata in answers]
            result['exists'] = True
        except:
            pass
        
        try:
            mx_records = dns.resolver.resolve(domain, 'MX')
            result['mx'] = [str(rdata.exchange) for rdata in mx_records]
        except:
            pass
        
        try:
            ns_records = dns.resolver.resolve(domain, 'NS')
            result['ns'] = [str(rdata) for rdata in ns_records]
        except:
            pass
        
        return result
    
    async def get_whois(self, domain: str) -> Optional[Dict]:
        """Obține informații WHOIS"""
        try:
            w = whois.whois(domain)
            return {
                'registrar': w.registrar,
                'creation_date': str(w.creation_date) if w.creation_date else None,
                'expiration_date': str(w.expiration_date) if w.expiration_date else None,
                'name_servers': w.name_servers if hasattr(w, 'name_servers') else []
            }
        except Exception as e:
            logger.debug(f"WHOIS failed for {domain}: {e}")
            return None
    
    async def fetch_with_playwright(self, url: str) -> Dict:
        """Fetch cu Playwright pentru JS rendering"""
        if not self.browser:
            await self.init_browser()
        
        try:
            page = await self.browser.new_page()
            await page.set_viewport_size({"width": 1920, "height": 1080})
            
            response = await page.goto(url, wait_until='networkidle', timeout=15000)
            
            screenshot_path = self.screenshots_dir / f"{hashlib.md5(url.encode()).hexdigest()}.png"
            await page.screenshot(path=str(screenshot_path), full_page=True)
            
            html = await page.content()
            title = await page.title()
            
            forms = await page.evaluate("""() => {
                return Array.from(document.querySelectorAll('form')).map(form => ({
                    action: form.action,
                    method: form.method,
                    inputs: Array.from(form.querySelectorAll('input')).map(inp => ({
                        type: inp.type,
                        name: inp.name
                    }))
                }));
            }""")
            
            links = await page.evaluate("""() => {
                return Array.from(document.querySelectorAll('a[href]')).map(a => a.href);
            }""")
            
            js_files = await page.evaluate("""() => {
                return Array.from(document.querySelectorAll('script[src]')).map(s => s.src);
            }""")
            
            await page.close()
            
            return {
                'success': True,
                'html': html,
                'title': title,
                'status': response.status if response else None,
                'screenshot': str(screenshot_path),
                'forms': forms,
                'links': links,
                'js_files': js_files,
                'redirects': []  
            }
            
        except Exception as e:
            logger.error(f"Playwright error for {url}: {e}")
            return {'success': False, 'error': str(e)}
    
    async def fetch_with_aiohttp(self, url: str) -> Dict:
        """Fallback cu aiohttp (fără JS)"""
        try:
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.get(url, ssl=self.ssl_context, allow_redirects=True) as response:
                    html = await response.text()
                    
                    return {
                        'success': True,
                        'html': html,
                        'title': self._extract_title(html),
                        'status': response.status,
                        'screenshot': None,
                        'forms': [],
                        'links': [],
                        'js_files': [],
                        'redirects': [str(h.url) for h in response.history]
                    }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def _extract_title(self, html: str) -> str:
        """Extrage titlul din HTML"""
        try:
            soup = BeautifulSoup(html, 'html.parser')
            title_tag = soup.find('title')
            return title_tag.text.strip() if title_tag else ""
        except:
            return ""
    
    def analyze_html(self, html: str) -> Dict:
        """Analiză avansată HTML pentru detectare phishing"""
        soup = BeautifulSoup(html, 'html.parser')
        
        indicators = []
        suspicious_keywords = []
        
     
        phishing_keywords = [
            'verify your account', 'suspended', 'urgent action', 'confirm your identity',
            'security alert', 'click here immediately', 'update payment', 'unusual activity',
            'limited time', 'act now', 'verify identity', 'account locked', 'restore access',
            'confirm payment', 'billing problem', 'expires today', 'claim your prize'
        ]
        
        text_content = soup.get_text().lower()
        for keyword in phishing_keywords:
            if keyword in text_content:
                suspicious_keywords.append(keyword)
                indicators.append(f"Phishing keyword: {keyword}")
        
  
        hidden_forms = soup.find_all('form', style=re.compile(r'display:\s*none'))
        if hidden_forms:
            indicators.append(f"Hidden forms detected: {len(hidden_forms)}")
        
        iframes = soup.find_all('iframe')
        if iframes:
            indicators.append(f"iframes found: {len(iframes)}")
        
        password_inputs = soup.find_all('input', {'type': 'password'})
        if password_inputs:
            indicators.append(f"Password fields: {len(password_inputs)}")
        
        scripts = soup.find_all('script')
        for script in scripts:
            if script.string and ('eval(' in script.string or 'unescape(' in script.string):
                indicators.append("Obfuscated JavaScript detected")
                break
        
        return {
            'suspicious_keywords': suspicious_keywords,
            'phishing_indicators': indicators
        }
    
    def calculate_similarity(self, html1: str, html2: str) -> float:
        """Calculează similaritate între două pagini HTML"""
        if not html1 or not html2:
            return 0.0
        
        soup1 = BeautifulSoup(html1, 'html.parser')
        soup2 = BeautifulSoup(html2, 'html.parser')
        
        text1 = soup1.get_text().strip()
        text2 = soup2.get_text().strip()
        
        return SequenceMatcher(None, text1, text2).ratio()
    
    def calculate_risk_score(self, result: Dict, similarity: float) -> int:
        """Calculează scor de risc 0-100"""
        score = 0
        
        if similarity > 0.7:
            score += 40
        elif similarity > 0.5:
            score += 25
        
        score += len(result.get('suspicious_keywords', [])) * 5
        
    
        score += len(result.get('phishing_indicators', [])) * 8
        
        if result.get('forms'):
            score += 15
        
    
        if len(result.get('redirects', [])) > 2:
            score += 10
        
        return min(score, 100)
    
    async def crawl_domain(self, domain: str) -> ThreatResult:
        """Crawl complet pentru un domeniu"""
        logger.info(f"Scanning: {domain}")
        
     
        dns_info = await self.check_dns(domain)
        
        if not dns_info['exists']:
            return ThreatResult(
                domain=domain, exists=False, ips=[], whois_data=None,
                status_code=None, title="", screenshot_path=None, html_hash="",
                similarity_score=0.0, risk_score=0, suspicious_keywords=[],
                phishing_indicators=[], ssl_info=None, redirects=[],
                forms_found=[], external_links=[], js_files=[],
                timestamp=datetime.now().isoformat()
            )
        
 
        whois_data = await self.get_whois(domain)
        
 
        url = f"https://{domain}"
        page_data = await self.fetch_with_playwright(url)
        
        if not page_data['success']:
            url = f"http://{domain}"
            page_data = await self.fetch_with_aiohttp(url)
        
        if not page_data['success']:
            return ThreatResult(
                domain=domain, exists=True, ips=dns_info['ips'], whois_data=whois_data,
                status_code=None, title="", screenshot_path=None, html_hash="",
                similarity_score=0.0, risk_score=50, suspicious_keywords=[],
                phishing_indicators=["Failed to fetch page"], ssl_info=None,
                redirects=[], forms_found=[], external_links=[], js_files=[],
                timestamp=datetime.now().isoformat()
            )
        
        html = page_data['html']
        html_hash = hashlib.sha256(html.encode()).hexdigest()
        analysis = self.analyze_html(html)
        
  
        similarity = 0.0
        if self.legitimate_html:
            similarity = self.calculate_similarity(html, self.legitimate_html)
        

        risk_score = self.calculate_risk_score(
            {**page_data, **analysis},
            similarity
        )
        
        return ThreatResult(
            domain=domain,
            exists=True,
            ips=dns_info['ips'],
            whois_data=whois_data,
            status_code=page_data.get('status'),
            title=page_data['title'],
            screenshot_path=page_data.get('screenshot'),
            html_hash=html_hash,
            similarity_score=similarity,
            risk_score=risk_score,
            suspicious_keywords=analysis['suspicious_keywords'],
            phishing_indicators=analysis['phishing_indicators'],
            ssl_info=None,  # TODO: add SSL cert analysis
            redirects=page_data.get('redirects', []),
            forms_found=page_data.get('forms', []),
            external_links=page_data.get('links', [])[:50],  
            js_files=page_data.get('js_files', [])[:20],
            timestamp=datetime.now().isoformat()
        )
    
    async def scan_target(self, target_domain: str, max_concurrent: int = 10):
        """Scanare completă pentru domeniul țintă"""
        logger.info(f"{'='*70}")
        logger.info(f"Starting advanced scan for: {target_domain}")
        logger.info(f"{'='*70}")
        
      
        logger.info("Fetching legitimate site for comparison...")
        legit_url = f"https://{target_domain}"
        legit_data = await self.fetch_with_playwright(legit_url)
        if legit_data['success']:
            self.legitimate_html = legit_data['html']
            self.legitimate_hash = hashlib.sha256(self.legitimate_html.encode()).hexdigest()
            logger.info("✓ Legitimate site captured")
        
  
        logger.info("Generating typosquat variants...")
        generator = AdvancedTypoGenerator()
        variants = generator.generate_all(target_domain)
        logger.info(f"✓ Generated {len(variants)} variants to check")
        
     
        semaphore = asyncio.Semaphore(max_concurrent)
        results = []
        
        async def bounded_scan(domain):
            async with semaphore:
                result = await self.crawl_domain(domain)
                if result.exists and result.risk_score > 30:
                    logger.warning(f"⚠️  THREAT: {domain} (Risk: {result.risk_score}/100)")
                return result
        
        tasks = [bounded_scan(domain) for domain in list(variants)[:100]]  # Limit for demo
        results = await asyncio.gather(*tasks)
        
      
        logger.info("Saving results to database...")
        scan_id = self.db.save_scan(target_domain, results)
        
    
        report = self._generate_report(target_domain, results, scan_id)
        
        
        report_path = self.output_dir / f"report_{scan_id}.json"
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2)
        
        logger.info(f"✓ Report saved: {report_path}")
        
        await self.close_browser()
        
        return report
    
    def _generate_report(self, target: str, results: List[ThreatResult], scan_id: int) -> Dict:
        """Generează raport final"""
        active = [r for r in results if r.exists]
        high_risk = [r for r in active if r.risk_score >= 70]
        medium_risk = [r for r in active if 40 <= r.risk_score < 70]
        low_risk = [r for r in active if r.risk_score < 40]
        
        return {
            'scan_id': scan_id,
            'target': target,
            'scan_time': datetime.now().isoformat(),
            'summary': {
                'total_checked': len(results),
                'active_domains': len(active),
                'high_risk': len(high_risk),
                'medium_risk': len(medium_risk),
                'low_risk': len(low_risk)
            },
            'threats': {
                'critical': [asdict(r) for r in sorted(high_risk, key=lambda x: x.risk_score, reverse=True)],
                'medium': [asdict(r) for r in sorted(medium_risk, key=lambda x: x.risk_score, reverse=True)][:10],
                'low': [asdict(r) for r in sorted(low_risk, key=lambda x: x.risk_score, reverse=True)][:5]
            }
        }


async def main():
    crawler = ThreatCrawler()
    
    # Target domain
    target = "youtube.com"
    
    report = await crawler.scan_target(target, max_concurrent=5)
    
    print(f"\n{'='*70}")
    print("THREAT INTELLIGENCE REPORT")
    print(f"{'='*70}")
    print(f"Target: {report['target']}")
    print(f"Scan ID: {report['scan_id']}")
    print(f"\nSummary:")
    print(f"  Total checked: {report['summary']['total_checked']}")
    print(f"  Active domains: {report['summary']['active_domains']}")
    print(f"  🔴 High risk: {report['summary']['high_risk']}")
    print(f"  🟡 Medium risk: {report['summary']['medium_risk']}")
    print(f"  🟢 Low risk: {report['summary']['low_risk']}")
    
    if report['threats']['critical']:
        print(f"\n{'='*70}")
        print("🚨 CRITICAL THREATS:")
        print(f"{'='*70}")
        for threat in report['threats']['critical'][:5]:
            print(f"\n  Domain: {threat['domain']}")
            print(f"  Risk Score: {threat['risk_score']}/100")
            print(f"  Similarity: {threat['similarity_score']:.2%}")
            print(f"  IPs: {', '.join(threat['ips'])}")
            if threat['phishing_indicators']:
                print(f"  Indicators: {', '.join(threat['phishing_indicators'][:3])}")


if __name__ == "__main__":

    asyncio.run(main())

    


    # ThreatCrawler - Advanced Phishing & Typosquat Detection System
#
# FUNCȚIONALITATE:
# - Generează automat 8 tipuri de variante typosquat:
#     * Homoglyphs
#     * Bitsquatting
#     * Character swap / omission / duplication
#     * Wrong TLDs
#     * Subdomain tricks
# - Verifică existența domeniilor prin DNS lookup (A, MX, NS records)
# - Extrage informații WHOIS (registrar, date creație/expirare, nameservers)
# - Crawlează paginile cu Playwright (headless browser pentru JS rendering)
# - Face screenshot-uri full-page automate pentru fiecare site activ
# - Analizează HTML pentru indicatori de phishing:
#     * Keywords suspecte (verify account, suspended, urgent action, etc.)
#     * Hidden forms și iframes
#     * Obfuscated JavaScript (eval, unescape)
#     * Password input fields
# - Calculează similaritate cu site-ul legitim (SequenceMatcher)
# - Generează risk score 0-100 bazat pe multipli factori
# - Salvează rezultate în SQLite DB cu indexuri optimizate
# - Exportă rapoarte JSON detaliate cu categorii (Critical / Medium / Low risk)
#
# OUTPUT:
# - threat_intel.db                 -> Bază de date cu istoric scanări
# - threat_data/report_{id}.json    -> Raport JSON complet
# - threat_data/screenshots/*.png   -> Screenshot-uri site-uri suspecte
#
# DEPENDENCIES:
# aiohttp, dnspython, certifi, beautifulsoup4, playwright, python-whois
#
# USAGE:
# asyncio.run(ThreatCrawler().scan_target("target-domain.com", max_concurrent=10))
