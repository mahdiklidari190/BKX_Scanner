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
██████╗ ██╗  ██╗
██╔══██╗██║  ██║
██████╔╝███████║
██╔═══╝ ██╔══██║
██║     ██║  ██║
╚═╝     ╚═╝  ╚═╝
"""

# FEATURES LIST
FEATURES = {
    "1": "Check Security Headers",
    "2": "Check IDOR",
    "3": "Check SSRF",
    "4": "Check Path Traversal",
    "5": "Check XSS",
    "6": "Check SQL Injection",
    "7": "Check RCE",
    "8": "Scan with Shodan",
    "9": "Scan Hidden Directories",
    "10": "Check Sensitive Files",
    "11": "Exit"
}

class BKXScanner:
    def __init__(self, target_url, shodan_api_key=None, proxy=None):
        self.target_url = target_url.rstrip("/")
        self.session = aiohttp.ClientSession()
        self.shodan_api_key = shodan_api_key
        self.proxy = proxy

    async def check_security_headers(self):
        """Check Security Headers"""
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
                    return f"Missing Security Headers: {missing_headers}"
                return "All Security Headers are present."
        except Exception as e:
            return f"Error Checking Headers: {str(e)}"

    async def scan_idor(self):
        """Check IDOR"""
        params = self.extract_params(self.target_url)
        return f"Parameters for IDOR Testing: {params}" if params else "No IDOR Parameters Found."

    async def scan_ssrf(self):
        """Check SSRF"""
        payload = "http://169.254.169.254/latest/meta-data/"
        try:
            async with self.session.get(urljoin(self.target_url, payload), proxy=self.proxy) as response:
                return "SSRF Vulnerability Detected!" if response.status == 200 else "No SSRF Found."
        except Exception as e:
            return f"SSRF Check Error: {str(e)}"

    async def scan_path_traversal(self):
        """Check Path Traversal"""
        test_url = f"{self.target_url}/../../etc/passwd"
        try:
            async with self.session.get(test_url, proxy=self.proxy) as response:
                return "Path Traversal Detected!" if "root:" in await response.text() else "No Path Traversal Found."
        except Exception as e:
            return f"Path Traversal Error: {str(e)}"

    async def scan_xss(self):
        """Check XSS"""
        payload = "<script>alert('XSS')</script>"
        try:
            async with self.session.get(f"{self.target_url}?search={payload}", proxy=self.proxy) as response:
                return "XSS Vulnerability Detected!" if payload in await response.text() else "No XSS Found."
        except Exception as e:
            return f"XSS Check Error: {str(e)}"

    async def shodan_scan(self):
        """Scan with Shodan"""
        if not self.shodan_api_key:
            return "Shodan API Key Missing."
        try:
            api = Shodan(self.shodan_api_key)
            target_ip = urlparse(self.target_url).netloc
            results = api.host(target_ip)
            return f"Shodan Scan Results:\n{results}"
        except Exception as e:
            return f"Shodan Scan Error: {str(e)}"

    def extract_params(self, url):
        """Extract Parameters from URL"""
        parsed_url = urlparse(url)
        query = parse_qs(parsed_url.query)
        return list(query.keys())

async def user_interface(stdscr):
    """Terminal User Interface"""
    curses.curs_set(0)
    stdscr.clear()
    stdscr.refresh()

    stdscr.addstr(1, 5, LOGO, curses.A_BOLD)
    stdscr.addstr(10, 5, "BKX Scanner Tools:", curses.A_UNDERLINE)

    row = 12
    for key, feature in FEATURES.items():
        stdscr.addstr(row, 7, f"[{key}] {feature}")
        row += 1

    stdscr.addstr(row + 2, 5, "Enter Your Choice:")
    stdscr.refresh()

    while True:
        key = stdscr.getch()
        key = chr(key)
        if key in FEATURES:
            return key

def main():
    os.system("clear")  
    print(LOGO)
    print("Welcome to BKX Scanner")
    
    target_url = input("Enter Target URL: ")
    shodan_key = os.getenv("SHODAN_API_KEY")
    proxy = input("Use Proxy? (yes/no): ").strip().lower() == "yes"
    
    scanner = BKXScanner(target_url, shodan_api_key=shodan_key, proxy=proxy)

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
        elif choice == "8":
            result = asyncio.run(scanner.shodan_scan())
        elif choice == "11":
            print("Exiting BKX Scanner.")
            break
        else:
            result = "Invalid Option!"

        print(f"\n[Result]: {result}\n")

if __name__ == "__main__":
    main()
