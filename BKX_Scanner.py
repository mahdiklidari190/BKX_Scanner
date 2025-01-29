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
    def __init__(self, target_url, shodan_api_key=None):
        self.target_url = target_url
        self.shodan_api_key = shodan_api_key
        self.session = None

    async def start_session(self):
        """ایجاد سشن برای درخواست‌های HTTP"""
        if not self.session:
            self.session = aiohttp.ClientSession()

    async def close_session(self):
        """بستن سشن بعد از اتمام اسکن"""
        if self.session:
            await self.session.close()

    async def request(self, url):
        """مدیریت درخواست HTTP با کنترل خطا"""
        try:
            async with self.session.get(url, timeout=5) as response:
                return await response.text() if response.status == 200 else None
        except Exception:
            return None

    async def scan_ssrf(self):
        """ بررسی SSRF """
        test_url = f"{self.target_url}/internal-api"
        print(f"{Fore.GREEN}Scanning {test_url} for SSRF...{Style.RESET_ALL}")

        result = await self.request(test_url)
        if result:
            return f"{Fore.RED}Possible SSRF vulnerability detected!{Style.RESET_ALL}"
        return f"{Fore.YELLOW}No SSRF vulnerability found.{Style.RESET_ALL}"

    async def scan_idor(self):
        """ بررسی IDOR """
        test_url = f"{self.target_url}/profile?user_id=1"
        print(f"{Fore.GREEN}Scanning {test_url} for IDOR...{Style.RESET_ALL}")

        result = await self.request(test_url)
        if result:
            return f"{Fore.RED}IDOR detected! You can access user data.{Style.RESET_ALL}"
        return f"{Fore.YELLOW}No IDOR vulnerability found.{Style.RESET_ALL}"

    async def scan_rce(self):
        """ بررسی RCE """
        test_url = f"{self.target_url}/run?cmd=whoami"
        print(f"{Fore.GREEN}Scanning {test_url} for RCE...{Style.RESET_ALL}")

        result = await self.request(test_url)
        if result and "root" in result:
            return f"{Fore.RED}Possible RCE detected!{Style.RESET_ALL}"
        return f"{Fore.YELLOW}No RCE vulnerability found.{Style.RESET_ALL}"

    async def scan_path_traversal(self):
        """ بررسی Path Traversal """
        test_url = f"{self.target_url}/download?file=../../etc/passwd"
        print(f"{Fore.GREEN}Scanning {test_url} for Path Traversal...{Style.RESET_ALL}")

        result = await self.request(test_url)
        if result and "root" in result:
            return f"{Fore.RED}Possible Path Traversal vulnerability found!{Style.RESET_ALL}"
        return f"{Fore.YELLOW}No Path Traversal vulnerability found.{Style.RESET_ALL}"

async def main():
    try:
        # پاک کردن صفحه
        os.system("cls" if os.name == "nt" else "clear")
        print(LOGO)

        target_url = input(f"{Fore.YELLOW}Enter target URL: {Style.RESET_ALL}")
        if not target_url.startswith("http"):
            print(f"{Fore.RED}Invalid URL! Please include http:// or https://{Style.RESET_ALL}")
            return

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
                print(f"{Fore.GREEN}Exiting...{Style.RESET_ALL}")
                break

            if choice in FEATURES:
                task_name = f"scan_{FEATURES[choice]}"
                task = getattr(scanner, task_name, None)

                if task:
                    result = await task()
                    print(result)
                    input(f"{Fore.YELLOW}Press Enter to continue...{Style.RESET_ALL}")

        await scanner.close_session()

    except KeyboardInterrupt:
        print(f"\n{Fore.RED}Interrupted by user!{Style.RESET_ALL}")
        await scanner.close_session()

    except Exception as e:
        print(f"{Fore.RED}Error: {str(e)}{Style.RESET_ALL}")

if __name__ == "__main__":
    asyncio.run(main())
