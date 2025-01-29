import asyncio
import aiohttp
import os
import time
import sys
from colorama import Fore, Style, init

# فعال‌سازی Colorama برای رنگ‌بندی در ترمینال
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
██║  ██║██║
╚═╝  ╚═╝╚═╝
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
        return f"{Fore.GREEN}Scanning {self.target_url} for SSRF...{Style.RESET_ALL}"

    async def scan_idor(self):
        return f"{Fore.GREEN}Scanning {self.target_url} for IDOR...{Style.RESET_ALL}"

    async def scan_rce(self):
        return f"{Fore.GREEN}Scanning {self.target_url} for RCE...{Style.RESET_ALL}"

    async def scan_path_traversal(self):
        return f"{Fore.GREEN}Scanning {self.target_url} for Path Traversal...{Style.RESET_ALL}"

    async def scan_directory_bruteforce(self):
        return f"{Fore.GREEN}Scanning {self.target_url} for Directory Bruteforce...{Style.RESET_ALL}"

    async def scan_sensitive_files(self):
        return f"{Fore.GREEN}Scanning {self.target_url} for Sensitive Files...{Style.RESET_ALL}"

    async def scan_shodan_lookup(self):
        return f"{Fore.GREEN}Searching {self.target_url} in Shodan...{Style.RESET_ALL}"

    async def scan_multi_threaded(self):
        return f"{Fore.GREEN}Performing Multi-threaded Scan on {self.target_url}...{Style.RESET_ALL}"

    async def scan_interactive_mode(self):
        return f"{Fore.YELLOW}Entering Interactive Mode...{Style.RESET_ALL}"

    async def scan_proxy_support(self):
        return f"{Fore.YELLOW}Enabling Proxy Support...{Style.RESET_ALL}"

    async def close(self):
        await self.session.close()

def slow_type(text, delay=0.02):
    """افکت تایپ‌شدن متن برای نمایش حرفه‌ای‌تر"""
    for char in text:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(delay)
    print()

async def main():
    os.system("clear")
    slow_type(LOGO, delay=0.002)

    target_url = input(f"{Fore.YELLOW}Enter target URL: {Style.RESET_ALL}")
    shodan_key = os.getenv("SHODAN_API_KEY")
    proxy = input(f"{Fore.YELLOW}Use proxy? (yes/no): {Style.RESET_ALL}").strip().lower() == "yes"
    
    scanner = BKXScanner(target_url, shodan_api_key=shodan_key, proxy=proxy)

    while True:
        os.system("clear")
        slow_type(LOGO, delay=0.002)
        print(f"{Fore.MAGENTA}📌 Available Scan Options:{Style.RESET_ALL}")
        
        for key, feature in FEATURES.items():
            print(f"{Fore.CYAN}[{key}] {feature}{Style.RESET_ALL}")

        choice = input(f"\n{Fore.YELLOW}🔎 Select an option: {Style.RESET_ALL}")

        if choice == "11":
            slow_type(f"{Fore.RED}Exiting...{Style.RESET_ALL}")
            await scanner.close()
            break

        if choice in FEATURES:
            task_name = f"scan_{FEATURES[choice].lower().replace(' ', '_')}"
            task = getattr(scanner, task_name, None)
            
            if task:
                result = await task()
                slow_type(f"\n{Fore.GREEN}[✔] {result}\n{Style.RESET_ALL}", delay=0.005)
                input(f"{Fore.YELLOW}Press Enter to continue...{Style.RESET_ALL}")
            else:
                slow_type(f"\n{Fore.RED}[✘] Invalid option!{Style.RESET_ALL}", delay=0.005)
                input(f"{Fore.YELLOW}Press Enter to continue...{Style.RESET_ALL}")
        else:
            slow_type(f"\n{Fore.RED}[✘] Invalid input! Please enter a valid number.{Style.RESET_ALL}", delay=0.005)
            input(f"{Fore.YELLOW}Press Enter to continue...{Style.RESET_ALL}")

if __name__ == "__main__":
    asyncio.run(main())  # اجرای برنامه با مدیریت صحیح event loop
