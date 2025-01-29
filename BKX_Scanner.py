import asyncio
import aiohttp
import os
import time
import sys
from colorama import Fore, Style, init

init(autoreset=True)

FEATURES = {
    "1": "SSRF Scan",
    "2": "IDOR Scan",
    "3": "RCE Scan",
    "4": "Path Traversal",
    "5": "Directory Bruteforce",
    "6": "Sensitive Files Scan",
    "7": "Shodan Lookup",
    "8": "Multi-threaded Scan",
    "9": "Interactive Mode",
    "10": "Proxy Support",
    "11": "Exit"
}

LOGO = f"""{Fore.CYAN}
 █████╗ ██╗
██╔══██╗██║
███████║██║
██╔══██║██║
██║  ██║███████╗
╚═╝  ╚═╝╚══════╝
{Style.RESET_ALL}"""

class BKXScanner:
    def __init__(self, target_url, shodan_api_key=None, proxy=False):
        self.target_url = target_url
        self.shodan_api_key = shodan_api_key
        self.proxy = proxy
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        self.session = aiohttp.ClientSession()

    async def scan_ssrf(self):
        """ بررسی SSRF با ارسال درخواست به یک URL داخلی """
        test_url = f"{self.target_url}/internal-api"
        print(f"{Fore.GREEN}Scanning {test_url} for SSRF...{Style.RESET_ALL}")
        
        try:
            async with self.session.get(test_url) as response:
                if response.status == 200:
                    return f"{Fore.RED}Possible SSRF vulnerability detected!{Style.RESET_ALL}"
                else:
                    return f"{Fore.YELLOW}No SSRF vulnerability found.{Style.RESET_ALL}"
        except Exception:
            return f"{Fore.YELLOW}Target did not respond to SSRF test.{Style.RESET_ALL}"

    async def scan_idor(self):
        """ تست IDOR با تغییر مقادیر شناسه """
        test_url = f"{self.target_url}/profile?user_id=1"
        print(f"{Fore.GREEN}Scanning {test_url} for IDOR...{Style.RESET_ALL}")

        async with self.session.get(test_url) as response:
            if response.status == 200:
                return f"{Fore.RED}IDOR detected! You can access user data.{Style.RESET_ALL}"
            return f"{Fore.YELLOW}No IDOR vulnerability found.{Style.RESET_ALL}"

    async def scan_rce(self):
        """ تست اجرای دستورات از راه دور """
        test_url = f"{self.target_url}/run?cmd=whoami"
        print(f"{Fore.GREEN}Scanning {test_url} for RCE...{Style.RESET_ALL}")

        async with self.session.get(test_url) as response:
            if response.status == 200 and "root" in await response.text():
                return f"{Fore.RED}Possible RCE detected!{Style.RESET_ALL}"
            return f"{Fore.YELLOW}No RCE vulnerability found.{Style.RESET_ALL}"

    async def scan_path_traversal(self):
        """ بررسی دسترسی غیرمجاز به فایل‌های سیستمی """
        test_url = f"{self.target_url}/download?file=../../etc/passwd"
        print(f"{Fore.GREEN}Scanning {test_url} for Path Traversal...{Style.RESET_ALL}")

        async with self.session.get(test_url) as response:
            if response.status == 200 and "root" in await response.text():
                return f"{Fore.RED}Possible Path Traversal vulnerability found!{Style.RESET_ALL}"
            return f"{Fore.YELLOW}No Path Traversal vulnerability found.{Style.RESET_ALL}"

    async def scan_directory_bruteforce(self):
        """ تست مسیرهای مخفی سایت """
        paths = ["/admin", "/backup", "/hidden"]
        for path in paths:
            url = f"{self.target_url}{path}"
            print(f"{Fore.GREEN}Checking {url}...{Style.RESET_ALL}")
            async with self.session.get(url) as response:
                if response.status == 200:
                    print(f"{Fore.RED}Found: {url}{Style.RESET_ALL}")

        return f"{Fore.YELLOW}Directory bruteforce scan completed.{Style.RESET_ALL}"

    async def scan_sensitive_files(self):
        """ بررسی وجود فایل‌های حساس """
        files = ["/.env", "/config.php", "/.git/config"]
        for file in files:
            url = f"{self.target_url}{file}"
            async with self.session.get(url) as response:
                if response.status == 200:
                    print(f"{Fore.RED}Sensitive file found: {url}{Style.RESET_ALL}")
        return f"{Fore.YELLOW}Sensitive file scan completed.{Style.RESET_ALL}"

    async def scan_shodan_lookup(self):
        """ بررسی اطلاعات سرور در Shodan """
        if not self.shodan_api_key:
            return f"{Fore.RED}Shodan API Key is missing.{Style.RESET_ALL}"

        async with self.session.get(f"https://api.shodan.io/shodan/host/{self.target_url}?key={self.shodan_api_key}") as response:
            return await response.text()

    async def scan_multi_threaded(self):
        """ اجرای چندین اسکن همزمان """
        tasks = [self.scan_ssrf(), self.scan_idor(), self.scan_rce()]
        results = await asyncio.gather(*tasks)
        return "\n".join(results)

    async def scan_interactive_mode(self):
        """ انتخاب چند اسکن به صورت تعاملی """
        print(f"{Fore.YELLOW}Select multiple scans:{Style.RESET_ALL}")
        selected = input("Enter scan numbers separated by commas: ").split(",")
        tasks = [getattr(self, f"scan_{FEATURES[s].lower().replace(' ', '_')}")() for s in selected if s in FEATURES]
        results = await asyncio.gather(*tasks)
        return "\n".join(results)

    async def scan_proxy_support(self):
        return f"{Fore.YELLOW}Proxy support enabled (not implemented yet).{Style.RESET_ALL}"

    async def close(self):
        await self.session.close()

async def main():
    os.system("clear")
    print(LOGO)

    target_url = input(f"{Fore.YELLOW}Enter target URL: {Style.RESET_ALL}")
    shodan_key = os.getenv("SHODAN_API_KEY")
    
    scanner = BKXScanner(target_url, shodan_api_key=shodan_key)

    while True:
        os.system("clear")
        print(LOGO)
        for key, feature in FEATURES.items():
            print(f"{Fore.CYAN}[{key}] {feature}{Style.RESET_ALL}")

        choice = input(f"\n{Fore.YELLOW}Select an option: {Style.RESET_ALL}")

        if choice == "11":
            await scanner.close()
            break

        if choice in FEATURES:
            task_name = f"scan_{FEATURES[choice].lower().replace(' ', '_')}"
            task = getattr(scanner, task_name, None)
            
            if task:
                result = await task()
                print(result)
                input(f"{Fore.YELLOW}Press Enter to continue...{Style.RESET_ALL}")
