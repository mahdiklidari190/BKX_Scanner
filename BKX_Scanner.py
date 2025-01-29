import asyncio
import aiohttp
import os
import curses

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

LOGO = """
██████╗ ██╗  ██╗██╗  ██╗    ███████╗ ██████╗ ██████╗ ███████╗
██╔══██╗██║ ██╔╝██║ ██╔╝    ██╔════╝██╔═══██╗██╔══██╗██╔════╝
██║  ██║█████╔╝ █████╔╝     █████╗  ██║   ██║██████╔╝█████╗  
██║  ██║██╔═██╗ ██╔═██╗     ██╔══╝  ██║   ██║██╔═══╝ ██╔══╝  
██████╔╝██║  ██╗██║  ██╗    ██║     ╚██████╔╝██║     ███████╗
╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝    ╚═╝      ╚═════╝ ╚═╝     ╚══════╝
"""

class BKXScanner:
    def __init__(self, target_url, shodan_api_key=None, proxy=False):
        self.target_url = target_url
        self.shodan_api_key = shodan_api_key
        self.proxy = proxy
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        self.session = aiohttp.ClientSession()

    async def scan_ssrf(self):
        return f"Scanning {self.target_url} for SSRF..."

    async def scan_idor(self):
        return f"Scanning {self.target_url} for IDOR..."

    async def scan_rce(self):
        return f"Scanning {self.target_url} for RCE..."

    async def scan_path_traversal(self):
        return f"Scanning {self.target_url} for Path Traversal..."

    async def scan_directory_bruteforce(self):
        return f"Scanning {self.target_url} for Directory Bruteforce..."

    async def scan_sensitive_files(self):
        return f"Scanning {self.target_url} for Sensitive Files..."

    async def scan_shodan_lookup(self):
        return f"Searching {self.target_url} in Shodan..."

    async def scan_multi_threaded(self):
        return f"Performing Multi-threaded Scan on {self.target_url}..."

    async def scan_interactive_mode(self):
        return "Entering Interactive Mode..."

    async def scan_proxy_support(self):
        return "Enabling Proxy Support..."

    async def close(self):
        await self.session.close()

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

async def main():
    target_url = input("Enter target URL: ")
    shodan_key = os.getenv("SHODAN_API_KEY")
    proxy = input("Use proxy? (yes/no): ").strip().lower() == "yes"
    
    scanner = BKXScanner(target_url, shodan_api_key=shodan_key, proxy=proxy)

    while True:
        choice = await curses.wrapper(user_interface)  # فراخوانی درست برای جلوگیری از coroutine object

        if choice == "11":
            print("Exiting...")
            await scanner.close()
            break

        task_name = f"scan_{FEATURES[choice].lower().replace(' ', '_')}"
        task = getattr(scanner, task_name, None)
        
        if task:
            result = await task()
            print(f"\n[Result]: {result}\n")
        else:
            print("\n[Error]: Invalid option!\n")

if __name__ == "__main__":
    asyncio.run(main())  # اجرای کامل برنامه با event loop مدیریت شده
