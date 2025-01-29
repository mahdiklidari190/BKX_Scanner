import asyncio
import aiohttp
import os
import sys
from colorama import Fore, Style, init

# تنظیمات colorama
init(autoreset=True)

# ویژگی‌های اسکنر
FEATURES = {
    "1": "ssrf",
    "2": "idor",
    "3": "rce",
    "4": "path_traversal",
    "5": "directory_bruteforce",
    "6": "sensitive_files_scan",
    "7": "shodan_lookup",
    "8": "multi_threaded_scan",
    "9": "interactive_mode",
    "10": "proxy_support",
    "11": "exit"
}

# لوگوی ابزار
LOGO = f"""{Fore.CYAN}
 █████╗ ██╗
██╔══██╗██║
███████║██║
██╔══██║██║
██║  ██║███████╗
╚═╝  ╚═╝╚══════╝
{Style.RESET_ALL}"""

class BKXScanner:
    def __init__(self, target_url, shodan_api_key=None, proxy=None):
        self.target_url = target_url
        self.shodan_api_key = shodan_api_key
        self.proxy = proxy
        self.session = None

    async def start_session(self):
        """ایجاد سشن برای درخواست‌های HTTP"""
        connector = None
        if self.proxy:
            connector = aiohttp.TCPConnector(ssl=False)
        self.session = aiohttp.ClientSession(connector=connector)

    async def close_session(self):
        """بستن سشن بعد از اتمام اسکن"""
        if self.session:
            await self.session.close()

    async def request(self, url):
        """مدیریت درخواست HTTP با کنترل خطا"""
        try:
            async with self.session.get(url, timeout=5, proxy=self.proxy) as response:
                return await response.text() if response.status == 200 else None
        except Exception:
            return None

    async def scan_ssrf(self):
        """بررسی SSRF"""
        test_url = f"{self.target_url}/internal-api"
        print(f"{Fore.GREEN}Scanning {test_url} for SSRF...{Style.RESET_ALL}")
        result = await self.request(test_url)
        return f"{Fore.RED}Possible SSRF vulnerability detected!{Style.RESET_ALL}" if result else f"{Fore.YELLOW}No SSRF vulnerability found.{Style.RESET_ALL}"

    async def scan_idor(self):
        """بررسی IDOR"""
        test_url = f"{self.target_url}/profile?user_id=1"
        print(f"{Fore.GREEN}Scanning {test_url} for IDOR...{Style.RESET_ALL}")
        result = await self.request(test_url)
        return f"{Fore.RED}IDOR detected! You can access user data.{Style.RESET_ALL}" if result else f"{Fore.YELLOW}No IDOR vulnerability found.{Style.RESET_ALL}"

    async def scan_rce(self):
        """بررسی RCE"""
        test_url = f"{self.target_url}/run?cmd=whoami"
        print(f"{Fore.GREEN}Scanning {test_url} for RCE...{Style.RESET_ALL}")
        result = await self.request(test_url)
        return f"{Fore.RED}Possible RCE detected!{Style.RESET_ALL}" if result and "root" in result else f"{Fore.YELLOW}No RCE vulnerability found.{Style.RESET_ALL}"

    async def scan_path_traversal(self):
        """بررسی Path Traversal"""
        test_url = f"{self.target_url}/download?file=../../etc/passwd"
        print(f"{Fore.GREEN}Scanning {test_url} for Path Traversal...{Style.RESET_ALL}")
        result = await self.request(test_url)
        return f"{Fore.RED}Possible Path Traversal vulnerability found!{Style.RESET_ALL}" if result and "root" in result else f"{Fore.YELLOW}No Path Traversal vulnerability found.{Style.RESET_ALL}"

    async def scan_directory_bruteforce(self):
        """جستجوی دایرکتوری‌های مخفی"""
        wordlist = ["admin", "login", "dashboard", "config", "uploads"]
        found = []
        for path in wordlist:
            url = f"{self.target_url}/{path}"
            print(f"{Fore.GREEN}Checking {url}...{Style.RESET_ALL}")
            result = await self.request(url)
            if result:
                found.append(url)
        return f"{Fore.RED}Found directories: {', '.join(found)}{Style.RESET_ALL}" if found else f"{Fore.YELLOW}No directories found.{Style.RESET_ALL}"

    async def scan_sensitive_files(self):
        """اسکن فایل‌های مهم"""
        files = ["robots.txt", ".git/", ".env", "config.php", "wp-config.php"]
        found = []
        for file in files:
            url = f"{self.target_url}/{file}"
            print(f"{Fore.GREEN}Checking {url}...{Style.RESET_ALL}")
            result = await self.request(url)
            if result:
                found.append(url)
        return f"{Fore.RED}Found sensitive files: {', '.join(found)}{Style.RESET_ALL}" if found else f"{Fore.YELLOW}No sensitive files found.{Style.RESET_ALL}"

    async def scan_shodan_lookup(self):
        """دریافت اطلاعات سرور از Shodan"""
        if not self.shodan_api_key:
            return f"{Fore.RED}No Shodan API key found!{Style.RESET_ALL}"
        url = f"https://api.shodan.io/shodan/host/{self.target_url}?key={self.shodan_api_key}"
        print(f"{Fore.GREEN}Fetching Shodan data...{Style.RESET_ALL}")
        result = await self.request(url)
        return result or f"{Fore.YELLOW}No data found on Shodan.{Style.RESET_ALL}"

    async def enable_proxy(self):
        """فعال کردن پروکسی"""
        self.proxy = "http://127.0.0.1:8080"
        return f"{Fore.GREEN}Proxy enabled: {self.proxy}{Style.RESET_ALL}"

async def main():
    os.system("cls" if os.name == "nt" else "clear")
    print(LOGO)

    target_url = input(f"{Fore.YELLOW}Enter target URL: {Style.RESET_ALL}")
    shodan_key = os.getenv("SHODAN_API_KEY")
    scanner = BKXScanner(target_url, shodan_api_key=shodan_key)

    await scanner.start_session()

    while True:
        os.system("cls" if os.name == "nt" else "clear")
        print(LOGO)
        for key, feature in FEATURES.items():
            print(f"{Fore.CYAN}[{key}] {feature.replace('_', ' ').title()}{Style.RESET_ALL}")

        choice = input(f"\n{Fore.YELLOW}Select an option: {Style.RESET_ALL}")
        if choice == "11":
            break

        task_name = f"scan_{FEATURES[choice]}"
        task = getattr(scanner, task_name, None)

        if task:
            result = await task()
            print(result)
            input(f"{Fore.YELLOW}Press Enter to continue...{Style.RESET_ALL}")

    await scanner.close_session()

if __name__ == "__main__":
    asyncio.run(main())
